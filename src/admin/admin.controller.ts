/* eslint-disable prettier/prettier */
import {
  Body,
  Controller,
  ForbiddenException,
  Get,
  Param,
  ParseUUIDPipe,
  Patch,
  Query,
  UseGuards,
} from '@nestjs/common';
import { JwtAuthGuard } from '../auth/guard/jwt-auth.guard';
import { CurrentUser } from '../auth/current-user';
import { SafeUser } from '../user/user.service';
import { FinanceService } from '../finance/finance.service';
import { UpdatePayoutStatusDto } from './dto/update-payout-status.dto';

@UseGuards(JwtAuthGuard)
@Controller('admin')
export class AdminController {
  constructor(private readonly financeService: FinanceService) {}

  private assertAdmin(user: SafeUser) {
    if (user.role !== 'ADMIN') {
      throw new ForbiddenException('Admin access only');
    }
  }

  @Get('payouts')
  getPayouts(
    @CurrentUser() user: SafeUser,
    @Query('farmerId') farmerId?: string,
    @Query('status') status?: string,
  ) {
    this.assertAdmin(user);
    return this.financeService.getPayoutsForAdmin(farmerId, status);
  }

  @Patch('payouts/:id/status')
  updatePayoutStatus(
    @CurrentUser() user: SafeUser,
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: UpdatePayoutStatusDto,
  ) {
    this.assertAdmin(user);
    return this.financeService.updatePayoutStatus(id, dto.status, dto.reason);
  }
}