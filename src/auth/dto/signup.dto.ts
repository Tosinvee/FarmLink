/* eslint-disable prettier/prettier */
import { IsEmail, IsIn, IsOptional, IsString, MinLength } from 'class-validator';

export class SignupDto {
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(8)
  password: string;

  @IsString()
  firstName: string;

  @IsOptional()
  @IsIn(['CONSUMER', 'FARMER'])
  role?: 'CONSUMER' | 'FARMER';
}