/* eslint-disable prettier/prettier */
import { Module } from '@nestjs/common';
import { AuthModule } from '../auth/auth.module';
import { FarmService } from './farm.service';
import { FarmController } from './farm.controller';

@Module({
  imports: [AuthModule],
  controllers: [FarmController],
  providers: [FarmService],
})
export class FarmModule {}