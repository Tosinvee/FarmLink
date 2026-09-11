import {
  BadGatewayException,
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { createHmac, timingSafeEqual } from 'crypto';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { SafeUser } from '../user/user.service';
import { PaystackService } from './paystack.service';
import { InitializePaymentDto } from './dto/initialize-payment.dto';
import { randomUUID } from 'crypto';

type Tx = Prisma.TransactionClient;

@Injectable()
export class PaymentService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly paystack: PaystackService,
  ) {}

  private validatePaystackPayment(
    payment: {
      amount: number;
      reference: string;
    },
    verification: {
      status: string;
      amount: number;
      reference: string;
    },
  ) {
    if (verification.status !== 'success') {
      throw new BadRequestException(
        `Payment is ${verification.status || 'not successful'}`,
      );
    }

    const expected = payment.amount * 100;
    const actual = Number(verification.amount);

    if (actual !== expected) {
      throw new BadRequestException('Payment amount mismatch');
    }

    if (verification.reference !== payment.reference) {
      throw new BadRequestException('Payment reference mismatch');
    }
  }

  private async getSettings(tx: Tx = this.prisma) {
    const settings = await tx.platformSetting.findUnique({ where: { id: 1 } });
    return {
      commissionRatePct: settings?.commissionRatePct ?? 8,
      minimumPayoutAmount: settings?.minimumPayoutAmount ?? 5000,
    };
  }

  private generateReference(prefix: string) {
    return `${prefix}_${randomUUID()}`;
  }

  async initializePayment(user: SafeUser, dto: InitializePaymentDto) {
    const order = await this.prisma.order.findFirst({
      where: {
        id: dto.orderId,
        userId: user.id,
      },
    });

    if (!order) {
      throw new NotFoundException('Order not found');
    }

    if (order.status !== 'PENDING_PAYMENT') {
      throw new BadRequestException('Order is not pending payment');
    }

    const existingPayment = await this.prisma.payment.findUnique({
      where: {
        orderId: order.id,
      },
    });

    if (existingPayment) {
      if (existingPayment.status === 'SUCCESSFUL') {
        throw new BadRequestException('Order has already been paid');
      }

      if (existingPayment.status === 'PROCESSING') {
        throw new BadRequestException('Payment is being processed');
      }

      if (
        existingPayment.status === 'PENDING' &&
        existingPayment.authorizationUrl
      ) {
        return {
          reference: existingPayment.reference,
          amount: existingPayment.amount,
          currency: 'NGN',
          authorizationUrl: existingPayment.authorizationUrl,
          accessCode: existingPayment.accessCode,
        };
      }
    }

    const reference = this.generateReference('FLK');

    const payment = await this.prisma.payment.create({
      data: {
        orderId: order.id,
        amount: order.total,
        reference,
        provider: 'paystack',
        status: 'PENDING',
      },
    });

    try {
      const initialization = await this.paystack.initializePayment(
        user.email,
        payment.amount * 100,
        payment.reference,
        {
          orderId: order.id,
        },
      );

      const updatedPayment = await this.prisma.payment.update({
        where: {
          id: payment.id,
        },
        data: {
          providerReference: initialization.reference,
          authorizationUrl: initialization.authorization_url,
          accessCode: initialization.access_code,
        },
      });

      return {
        reference: updatedPayment.reference,
        amount: updatedPayment.amount,
        currency: 'NGN',
        authorizationUrl: updatedPayment.authorizationUrl,
        accessCode: updatedPayment.accessCode,
      };
    } catch (error) {
      await this.prisma.payment.delete({
        where: {
          id: payment.id,
        },
      });

      throw new BadRequestException(
        'Unable to initialize payment. Please try again.',
      );
    }
  }
  async verifyPayment(user: SafeUser, reference: string) {
    const payment = await this.prisma.payment.findUnique({
      where: { reference },
      include: { order: true },
    });
    if (!payment || payment.order.userId !== user.id) {
      throw new NotFoundException('Payment not found');
    }

    if (payment.status === 'SUCCESSFUL' || payment.status === 'PROCESSING') {
      return payment;
    }

    const claimed = await this.claimPayment(payment.id);
    if (!claimed) {
      return this.prisma.payment.findUnique({ where: { id: payment.id } });
    }

    try {
      const verification = await this.paystack.verifyPayment(payment.reference);

      await this.validatePaystackPayment(payment, verification);

      return await this.settlePayment(payment.id, verification);
    } catch (error) {
      if (error instanceof BadRequestException) {
        throw error;
      }
      await this.revertPayment(payment.id);
      throw new BadGatewayException('Payment verification failed');
    }
  }

  async handlePaystackWebhook(rawBody: Buffer, signature?: string | string[]) {
    const secret = this.paystack.getSecretKey();

    if (
      !secret ||
      !signature ||
      typeof signature !== 'string' ||
      rawBody.length === 0
    ) {
      throw new BadRequestException('Invalid webhook signature');
    }

    const hash = createHmac('sha512', secret).update(rawBody).digest();
    const signatureBuffer = Buffer.from(signature, 'hex');

    if (
      signatureBuffer.length !== hash.length ||
      !timingSafeEqual(hash, signatureBuffer)
    ) {
      throw new BadRequestException('Invalid webhook signature');
    }

    const body = JSON.parse(rawBody.toString('utf8'));

    if (body.event !== 'charge.success') {
      return { received: true };
    }

    const reference = body.data?.reference;
    if (!reference) {
      return { received: true };
    }

    const payment = await this.prisma.payment.findUnique({
      where: { reference },
    });
    if (!payment) {
      return { received: true };
    }

    const claimed = await this.claimPayment(payment.id);
    if (!claimed) {
      return { received: true };
    }

    try {
      const verification = await this.paystack.verifyPayment(reference);
      await this.validatePaystackPayment(payment, verification);
      if (verification.status === 'success') {
        await this.settlePayment(payment.id, verification);
      } else {
        await this.revertPayment(payment.id);
      }
    } catch {
      await this.revertPayment(payment.id);
    }

    return { received: true };
  }

  private async claimPayment(paymentId: string) {
    const result = await this.prisma.payment.updateMany({
      where: { id: paymentId, status: 'PENDING' },
      data: { status: 'PROCESSING' },
    });
    return result.count > 0;
  }

  private async revertPayment(paymentId: string) {
    await this.prisma.payment.updateMany({
      where: { id: paymentId, status: 'PROCESSING' },
      data: { status: 'PENDING' },
    });
  }

  private async settlePayment(
    paymentId: string,
    verification: { status: string; amount: number; reference: string },
  ) {
    return this.prisma.$transaction(async (tx) => {
      const payment = await tx.payment.findUnique({
        where: { id: paymentId },
        include: { order: true },
      });
      if (!payment) {
        throw new NotFoundException('Payment not found');
      }
      if (payment.status === 'SUCCESSFUL') {
        return payment;
      }

      await tx.payment.update({
        where: { id: paymentId },
        data: {
          status: 'SUCCESSFUL',
          paidAt: new Date(),
          gatewayResponse: verification as unknown as Prisma.InputJsonValue,
        },
      });

      await tx.order.update({
        where: { id: payment.orderId },
        data: { status: 'CONFIRMED' },
      });

      const settings = await this.getSettings(tx);
      const gross = payment.order.subtotal;
      const platformCommission = Math.round(
        (gross * settings.commissionRatePct) / 100,
      );
      const netAmount = gross - platformCommission;

      try {
        await tx.farmerEarning.create({
          data: {
            farmerId: payment.order.farmerId,
            orderId: payment.order.id,
            grossAmount: gross,
            platformCommission,
            netAmount,
          },
        });
      } catch (error) {
        if (
          error instanceof Prisma.PrismaClientKnownRequestError &&
          error.code === 'P2002'
        ) {
          // earning already exists for this order (idempotent)
        } else {
          throw error;
        }
      }

      return tx.payment.findUnique({
        where: { id: paymentId },
        include: { order: true },
      });
    });
  }
}
