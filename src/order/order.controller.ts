/* eslint-disable prettier/prettier */
import {
  Body,
  Controller,
  Get,
  Param,
  ParseUUIDPipe,
  Post,
  UseGuards,
} from '@nestjs/common';
import { JwtAuthGuard } from '../auth/guard/jwt-auth.guard';
import { CurrentUser } from '../auth/current-user';
import { SafeUser } from '../user/user.service';
import { OrderService } from './order.service';
import { CreateOrderDto } from './dto/create-order.dto';

@UseGuards(JwtAuthGuard)
@Controller('orders')
export class OrderController {
  constructor(private readonly orderService: OrderService) {}

  @Get()
  findMine(@CurrentUser() user: SafeUser) {
    return this.orderService.findAll(user.id);
  }

  @Get(':id')
  findOne(
    @CurrentUser() user: SafeUser,
    @Param('id', ParseUUIDPipe) id: string,
  ) {
    return this.orderService.findOne(user.id, id);
  }

  @Post()
  checkout(@CurrentUser() user: SafeUser, @Body() dto: CreateOrderDto) {
    return this.orderService.checkout(user.id, dto);
  }
}
