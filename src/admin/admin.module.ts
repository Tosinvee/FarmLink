/* eslint-disable prettier/prettier */
import { Module } from '@nestjs/common';
import { FinanceModule } from '../finance/finance.module';
import { AdminController } from './admin.controller';

@Module({
  imports: [FinanceModule],
  controllers: [AdminController],
})
export class AdminModule {}