/* eslint-disable prettier/prettier */
import { IsOptional, IsString, MaxLength } from 'class-validator';

export class UpdateFarmerDto {
  @IsOptional()
  @IsString()
  @MaxLength(100)
  displayName?: string;

  @IsOptional()
  @IsString()
  @MaxLength(500)
  description?: string;
}