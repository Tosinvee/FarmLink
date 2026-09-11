/* eslint-disable prettier/prettier */
import {
  Body,
  Controller,
  Get,
  Param,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { Request } from 'express';
import { JwtAuthGuard } from '../auth/guard/jwt-auth.guard';
import { CurrentUser } from '../auth/current-user';
import { SafeUser } from '../user/user.service';
import { PaymentService } from './payment.service';
import { InitializePaymentDto } from './dto/initialize-payment.dto';

@Controller('payments')
export class PaymentController {
  constructor(private readonly paymentService: PaymentService) {}

  @Post('initialize')
  @UseGuards(JwtAuthGuard)
  initialize(@CurrentUser() user: SafeUser, @Body() dto: InitializePaymentDto) {
    return this.paymentService.initializePayment(user, dto);
  }

  @Get('verify/:reference')
  @UseGuards(JwtAuthGuard)
  verify(
    @CurrentUser() user: SafeUser,
    @Param('reference') reference: string,
  ) {
    return this.paymentService.verifyPayment(user, reference);
  }

  @Post('paystack/webhook')
  async handleWebhook(@Req() req: Request) {
    const rawBody = (req as any).rawBody as Buffer | undefined;
    const signature = req.headers?.['x-paystack-signature'] as
      | string
      | string[]
      | undefined;
    return this.paymentService.handlePaystackWebhook(rawBody ?? Buffer.alloc(0), signature);
  }
}