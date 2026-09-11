import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AddCartItemDto } from './dto/add-cart-item.dto';
import { UpdateCartItemDto } from './dto/update-cart-item.dto';

const cartItemInclude = {
  product: {
    select: {
      id: true,
      name: true,
      price: true,
      farmerId: true,
      unit: true,
      imageUrl: true,
      isAvailable: true,
      quantity: true,
      farm: { select: { id: true, name: true } },
      category: { select: { name: true } },
    },
  },
} as const;

@Injectable()
export class CartService {
  constructor(private readonly prisma: PrismaService) {}

  private async getOrCreateCart(userId: string) {
    let cart = await this.prisma.cart.findUnique({
      where: { userId },
      include: { items: { include: cartItemInclude } },
    });

    if (!cart) {
      cart = await this.prisma.cart.create({
        data: { userId },
        include: { items: { include: cartItemInclude } },
      });
    }

    return cart;
  }

  private async getProduct(productId: string) {
    const product = await this.prisma.product.findUnique({
      where: { id: productId },
    });
    if (!product) {
      throw new NotFoundException('Product not found');
    }
    return product;
  }

  private assertInStock(
    product: { isAvailable: boolean; quantity: number },
    requested: number,
  ) {
    if (!product.isAvailable) {
      throw new BadRequestException('Product is not available');
    }
    if (product.quantity < requested) {
      throw new BadRequestException('Not enough stock available');
    }
  }

  async getCart(userId: string) {
    const cart = await this.getOrCreateCart(userId);
    return this.buildCartResponse(cart);
  }

  async addItem(userId: string, dto: AddCartItemDto) {
    const cart = await this.getOrCreateCart(userId);
    const product = await this.getProduct(dto.productId);

    const otherFarmerItem = cart.items.find(
      (item) => item.product.farmerId !== product.farmerId,
    );
    if (otherFarmerItem) {
      throw new BadRequestException(
        'Cart already contains items from another farm. Clear the cart first.',
      );
    }

    const existing = await this.prisma.cartItem.findUnique({
      where: {
        cartId_productId: { cartId: cart.id, productId: dto.productId },
      },
    });

    const quantity = (existing ? existing.quantity : 0) + dto.quantity;
    this.assertInStock(product, quantity);

    await this.prisma.cartItem.upsert({
      where: {
        cartId_productId: {
          cartId: cart.id,
          productId: dto.productId,
        },
      },
      create: {
        cartId: cart.id,
        productId: dto.productId,
        quantity: dto.quantity,
      },
      update: { quantity },
    });

    return this.getCart(userId);
  }

  async updateItem(userId: string, productId: string, dto: UpdateCartItemDto) {
    const cart = await this.getOrCreateCart(userId);
    const cartId = cart.id;

    const existing = await this.prisma.cartItem.findUnique({
      where: { cartId_productId: { cartId, productId } },
    });
    if (!existing) {
      throw new NotFoundException('Cart item not found');
    }

    const product = await this.getProduct(productId);
    this.assertInStock(product, dto.quantity);

    await this.prisma.cartItem.update({
      where: { cartId_productId: { cartId, productId } },
      data: { quantity: dto.quantity },
    });

    return this.getCart(userId);
  }

  async removeItem(userId: string, productId: string) {
    const cart = await this.getOrCreateCart(userId);

    const existing = await this.prisma.cartItem.findUnique({
      where: { cartId_productId: { cartId: cart.id, productId } },
    });
    if (!existing) {
      throw new NotFoundException('Cart item not found');
    }

    await this.prisma.cartItem.delete({
      where: { id: existing.id },
    });

    return this.getCart(userId);
  }

  async clear(userId: string) {
    const cart = await this.getOrCreateCart(userId);
    await this.prisma.cartItem.deleteMany({ where: { cartId: cart.id } });
    return this.getCart(userId);
  }

  private buildCartResponse(cart: {
    id: string;
    items: { quantity: number; product: { price: number } }[];
  }) {
    const subtotal = cart.items.reduce(
      (sum, item) => sum + item.product.price * item.quantity,
      0,
    );
    return {
      id: cart.id,
      items: cart.items,
      subtotal,
      itemCount: cart.items.reduce((sum, item) => sum + item.quantity, 0),
    };
  }
}
