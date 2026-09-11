/* eslint-disable prettier/prettier */
import { Body, Controller, Get, Post, Put, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../auth/guard/jwt-auth.guard';
import { CurrentUser } from '../auth/current-user';
import { SafeUser } from '../user/user.service';
import { FinanceService } from './finance.service';
import { UpsertPayoutAccountDto } from './dto/upsert-payout-account.dto';
import { RequestPayoutDto } from './dto/request-payout.dto';

@UseGuards(JwtAuthGuard)
@Controller('finance')
export class FinanceController {
  constructor(private readonly financeService: FinanceService) {}

  @Put('payout-account')
  upsertPayoutAccount(
    @CurrentUser() user: SafeUser,
    @Body() dto: UpsertPayoutAccountDto,
  ) {
    return this.financeService.upsertPayoutAccount(user, dto);
  }

  @Get('payout-account')
  getPayoutAccount(@CurrentUser() user: SafeUser) {
    return this.financeService.getPayoutAccount(user);
  }

  @Get('earnings')
  getEarnings(@CurrentUser() user: SafeUser) {
    return this.financeService.getEarnings(user);
  }

  @Get('earnings/summary')
  getEarningsSummary(@CurrentUser() user: SafeUser) {
    return this.financeService.getEarningsSummary(user);
  }

  @Post('payouts/request')
  requestPayout(@CurrentUser() user: SafeUser, @Body() dto: RequestPayoutDto) {
    return this.financeService.requestPayout(user, dto);
  }

  @Get('payouts')
  getPayouts(@CurrentUser() user: SafeUser) {
    return this.financeService.getPayouts(user);
  }
}