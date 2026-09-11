/* eslint-disable prettier/prettier */
import { IsInt, IsOptional, IsUUID, Min } from 'class-validator';

export class CreateOrderDto {
  @IsOptional()
  @IsUUID()
  addressId?: string;

  @IsOptional()
  @IsInt()
  @Min(0)
  deliveryFee?: number;
}