/* eslint-disable prettier/prettier */
import { IsEnum, IsOptional, IsString } from 'class-validator';

export enum AdminPayoutStatus {
  PAID = 'PAID',
  FAILED = 'FAILED',
}

export class UpdatePayoutStatusDto {
  @IsEnum(AdminPayoutStatus)
  status: AdminPayoutStatus;

  @IsOptional()
  @IsString()
  reason?: string;
}