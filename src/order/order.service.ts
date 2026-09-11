import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CreateOrderDto } from './dto/create-order.dto';

const orderInclude = {
  items: true,
  address: {
    select: {
      fullName: true,
      phone: true,
      street: true,
      city: true,
      state: true,
      country: true,
    },
  },
  payment: true,
  delivery: true,
} as const;

@Injectable()
export class OrderService {
  constructor(private readonly prisma: PrismaService) {}

  async checkout(userId: string, dto: CreateOrderDto) {
    return this.prisma.$transaction(async (tx) => {
      const cart = await tx.cart.findUnique({
        where: { userId },
        include: { items: { include: { product: true } } },
      });

      if (!cart || cart.items.length === 0) {
        throw new BadRequestException('Cart is empty');
      }

      if (dto.addressId) {
        const address = await tx.address.findFirst({
          where: { id: dto.addressId, userId },
        });
        if (!address) {
          throw new BadRequestException('Address not found for this user');
        }
      }

      const farmerId = cart.items[0].product.farmerId;
      if (!cart.items.every((i) => i.product.farmerId === farmerId)) {
        throw new BadRequestException(
          'Cart contains items from multiple farms',
        );
      }

      const orderItems = [];
      let subtotal = 0;

      for (const item of cart.items) {
        const product = item.product;

        if (!product.isAvailable) {
          throw new BadRequestException(
            `Product "${product.name}" is not available`,
          );
        }
        if (product.quantity < item.quantity) {
          throw new BadRequestException(
            `Not enough stock for "${product.name}"`,
          );
        }

        const unitPrice = product.price;
        const totalPrice = unitPrice * item.quantity;
        subtotal += totalPrice;

        orderItems.push({
          productId: product.id,
          productName: product.name,
          productImage: product.imageUrl,
          unitPrice,
          quantity: item.quantity,
          totalPrice,
        });
      }

      const deliveryFee = dto.deliveryFee ?? 0;
      const order = await tx.order.create({
        data: {
          userId,
          farmerId,
          addressId: dto.addressId ?? null,
          subtotal,
          deliveryFee,
          total: subtotal + deliveryFee,
          items: { create: orderItems },
        },
        include: orderInclude,
      });

      for (const item of cart.items) {
        const result = await tx.product.updateMany({
          where: {
            id: item.productId,
            isAvailable: true,
            quantity: {
              gte: item.quantity,
            },
          },
          data: {
            quantity: {
              decrement: item.quantity,
            },
          },
        });

        if (result.count === 0) {
          throw new BadRequestException(
            `Not enough stock for "${item.product.name}"`,
          );
        }
      }

      await tx.cartItem.deleteMany({ where: { cartId: cart.id } });

      return order;
    });
  }

  findAll(userId: string) {
    return this.prisma.order.findMany({
      where: { userId },
      include: orderInclude,
      orderBy: { createdAt: 'desc' },
    });
  }

  async findOne(userId: string, id: string) {
    const order = await this.prisma.order.findFirst({
      where: { id, userId },
      include: orderInclude,
    });
    if (!order) {
      throw new NotFoundException('Order not found');
    }
    return order;
  }
}
