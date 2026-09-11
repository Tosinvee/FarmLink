/* eslint-disable prettier/prettier */
import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { SafeUser } from '../user/user.service';
import { UpsertPayoutAccountDto } from './dto/upsert-payout-account.dto';
import { RequestPayoutDto } from './dto/request-payout.dto';

@Injectable()
export class FinanceService {
  private readonly MIN_PAYOUT_DEFAULT = 5000;

  constructor(private readonly prisma: PrismaService) {}

  private async getOwnFarmer(user: SafeUser) {
    if (user.role !== 'FARMER') {
      throw new ForbiddenException('Only farmers can access finance');
    }
    const farmer = await this.prisma.farmer.findUnique({
      where: { userId: user.id },
    });
    if (!farmer) {
      throw new ForbiddenException('Farmer profile not found');
    }
    return farmer;
  }

  private maskAccountNumber(number: string) {
    return `****${number.slice(-4)}`;
  }

  private async getMinimumPayout() {
    const settings = await this.prisma.platformSetting.findUnique({
      where: { id: 1 },
    });
    return settings?.minimumPayoutAmount ?? this.MIN_PAYOUT_DEFAULT;
  }

  async upsertPayoutAccount(user: SafeUser, dto: UpsertPayoutAccountDto) {
    const farmer = await this.getOwnFarmer(user);

    const existing = await this.prisma.farmerPayoutAccount.findUnique({
      where: { farmerId: farmer.id },
    });

    const account = existing
      ? await this.prisma.farmerPayoutAccount.update({
          where: { id: existing.id },
          data: dto,
        })
      : await this.prisma.farmerPayoutAccount.create({
          data: { ...dto, farmerId: farmer.id },
        });

    return {
      id: account.id,
      bankName: account.bankName,
      accountName: account.accountName,
      accountNumber: this.maskAccountNumber(account.accountNumber),
      bankCode: account.bankCode,
      isVerified: account.isVerified,
    };
  }

  async getPayoutAccount(user: SafeUser) {
    const farmer = await this.getOwnFarmer(user);

    const account = await this.prisma.farmerPayoutAccount.findUnique({
      where: { farmerId: farmer.id },
    });
    if (!account) {
      throw new NotFoundException('Payout account not found');
    }

    return {
      id: account.id,
      bankName: account.bankName,
      accountName: account.accountName,
      accountNumber: this.maskAccountNumber(account.accountNumber),
      bankCode: account.bankCode,
      isVerified: account.isVerified,
    };
  }

  async getEarnings(user: SafeUser) {
    const farmer = await this.getOwnFarmer(user);
    return this.prisma.farmerEarning.findMany({
      where: { farmerId: farmer.id },
      orderBy: { earnedAt: 'desc' },
    });
  }

  async getEarningsSummary(user: SafeUser) {
    const farmer = await this.getOwnFarmer(user);

    const [earnings, payouts] = await Promise.all([
      this.prisma.farmerEarning.findMany({ where: { farmerId: farmer.id } }),
      this.prisma.farmerPayout.findMany({ where: { farmerId: farmer.id } }),
    ]);

    const totalEarned = earnings.reduce(
      (sum, e) => sum + e.netAmount,
      0,
    );
    const pendingPayoutAmount = payouts
      .filter(
        (p) => p.status === 'PENDING' || p.status === 'PROCESSING',
      )
      .reduce((sum, p) => sum + p.amount, 0);
    const paidPayoutAmount = payouts
      .filter((p) => p.status === 'PAID')
      .reduce((sum, p) => sum + p.amount, 0);

    return {
      totalEarned,
      pendingPayoutAmount,
      paidPayoutAmount,
      availableBalance: totalEarned - pendingPayoutAmount - paidPayoutAmount,
      minimumPayoutAmount: await this.getMinimumPayout(),
    };
  }

  async requestPayout(user: SafeUser, dto: RequestPayoutDto) {
    const farmer = await this.getOwnFarmer(user);

    const account = await this.prisma.farmerPayoutAccount.findUnique({
      where: { farmerId: farmer.id },
    });
    if (!account) {
      throw new BadRequestException('Payout account not found');
    }

    const summary = await this.getEarningsSummary(user);
    if (dto.amount < summary.minimumPayoutAmount) {
      throw new BadRequestException(
        `Minimum payout amount is NGN ${summary.minimumPayoutAmount}`,
      );
    }
    if (dto.amount > summary.availableBalance) {
      throw new BadRequestException('Insufficient available balance');
    }

    return this.prisma.farmerPayout.create({
      data: {
        farmerId: farmer.id,
        payoutAccountId: account.id,
        amount: dto.amount,
        reference: this.generateReference('PAYOUT'),
      },
    });
  }

  async getPayouts(user: SafeUser) {
    const farmer = await this.getOwnFarmer(user);
    return this.prisma.farmerPayout.findMany({
      where: { farmerId: farmer.id },
      orderBy: { createdAt: 'desc' },
    });
  }

  async getPayoutsForAdmin(farmerId?: string, status?: string) {
    const where: Record<string, unknown> = {};
    if (farmerId) {
      where.farmerId = farmerId;
    }
    if (status) {
      where.status = status;
    }

    const [payouts, pendingApproval, paidToday, failedToday] =
      await Promise.all([
        this.prisma.farmerPayout.findMany({
          where,
          orderBy: { createdAt: 'desc' },
          include: {
            farmer: { select: { displayName: true } },
            payoutAccount: {
              select: {
                bankName: true,
                accountName: true,
                accountNumber: true,
              },
            },
          },
        }),
        this.prisma.farmerPayout.count({ where: { status: 'PENDING' } }),
        this.prisma.farmerPayout.count({
          where: {
            status: 'PAID',
            processedAt: { gte: new Date(new Date().setHours(0, 0, 0, 0)) },
          },
        }),
        this.prisma.farmerPayout.count({ where: { status: 'FAILED' } }),
      ]);

    return {
      metrics: { pendingApproval, paidToday, failedToday },
      payouts,
    };
  }

  async updatePayoutStatus(
    payoutId: string,
    status: 'PAID' | 'FAILED',
    reason?: string,
  ) {
    const payout = await this.prisma.farmerPayout.findUnique({
      where: { id: payoutId },
    });
    if (!payout) {
      throw new NotFoundException('Payout not found');
    }
    if (payout.status !== 'PENDING') {
      throw new BadRequestException(
        `Cannot update payout with status ${payout.status}`,
      );
    }

    return this.prisma.farmerPayout.update({
      where: { id: payoutId },
      data: {
        status,
        processedAt: new Date(),
        failureReason: status === 'FAILED' ? reason || 'Declined by admin' : null,
      },
    });
  }

  private generateReference(prefix: string) {
    return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
  }
}