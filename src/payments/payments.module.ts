/* eslint-disable prettier/prettier */
import { Module } from '@nestjs/common';
import { PaymentController } from './payment.controller';
import { PaymentService } from './payment.service';
import { PaystackService } from './paystack.service';

@Module({
  controllers: [PaymentController],
  providers: [PaymentService, PaystackService],
})
export class PaymentsModule {}