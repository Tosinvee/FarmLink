/* eslint-disable prettier/prettier */
import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { SafeUser } from '../user/user.service';
import { CreateProductDto } from './dto/create-product.dto';
import { UpdateProductDto } from './dto/update-product.dto';
import { SearchProductsDto } from './dto/search-products.dto';

@Injectable()
export class ProductsService {
  constructor(private readonly prisma: PrismaService) {}

  private productInclude = {
    category: { select: { id: true, name: true } },
    farm: { select: { name: true } },
    farmer: { select: { id: true, displayName: true } },
  } as const;

  private async getOwnFarmer(user: SafeUser) {
    if (user.role !== 'FARMER') {
      throw new ForbiddenException('Only farmer accounts can manage products');
    }

    const farmer = await this.prisma.farmer.findUnique({
      where: { userId: user.id },
    });
    if (!farmer) {
      throw new ForbiddenException('Farmer profile not found');
    }

    return farmer;
  }

  private async assertCategoryExists(categoryId: string) {
    const category = await this.prisma.category.findUnique({
      where: { id: categoryId },
    });
    if (!category) {
      throw new BadRequestException('Category not found');
    }
  }

  findAll(query: SearchProductsDto) {
    const where: Prisma.ProductWhereInput = { isAvailable: true };

    if (query.search) {
      where.OR = [
        { name: { contains: query.search, mode: 'insensitive' } },
        { description: { contains: query.search, mode: 'insensitive' } },
      ];
    }
    if (query.categoryId) {
      where.categoryId = query.categoryId;
    }
    if (query.farmerId) {
      where.farmerId = query.farmerId;
    }
    if (query.minPrice !== undefined || query.maxPrice !== undefined) {
      where.price = {};
      if (query.minPrice !== undefined) {
        where.price.gte = query.minPrice;
      }
      if (query.maxPrice !== undefined) {
        where.price.lte = query.maxPrice;
      }
    }

    let orderBy: Prisma.ProductOrderByWithRelationInput = { name: 'asc' };
    if (query.sort === 'newest') {
      orderBy = { createdAt: 'desc' };
    } else if (query.sort === 'price_asc') {
      orderBy = { price: 'asc' };
    } else if (query.sort === 'price_desc') {
      orderBy = { price: 'desc' };
    }

    return this.prisma.product.findMany({
      where,
      orderBy,
      include: this.productInclude,
    });
  }

  async findOne(id: string) {
    const product = await this.prisma.product.findUnique({
      where: { id },
      include: this.productInclude,
    });
    if (!product) {
      throw new NotFoundException('Product not found');
    }
    return product;
  }

  async create(user: SafeUser, dto: CreateProductDto) {
    const farmer = await this.getOwnFarmer(user);
    await this.assertCategoryExists(dto.categoryId);

    const farm = await this.prisma.farm.findUnique({
      where: { farmerId: farmer.id },
    });

    return this.prisma.product.create({
      data: {
        ...dto,
        farmerId: farmer.id,
        farmId: farm ? farm.id : null,
      },
      include: this.productInclude,
    });
  }

  async update(user: SafeUser, id: string, dto: UpdateProductDto) {
    const farmer = await this.getOwnFarmer(user);

    const product = await this.prisma.product.findUnique({ where: { id } });
    if (!product) {
      throw new NotFoundException('Product not found');
    }
    if (product.farmerId !== farmer.id) {
      throw new ForbiddenException('You can only update your own products');
    }

    if (dto.categoryId) {
      await this.assertCategoryExists(dto.categoryId);
    }

    return this.prisma.product.update({
      where: { id },
      data: dto,
      include: this.productInclude,
    });
  }

  async remove(user: SafeUser, id: string) {
    const farmer = await this.getOwnFarmer(user);

    const product = await this.prisma.product.findUnique({ where: { id } });
    if (!product) {
      throw new NotFoundException('Product not found');
    }
    if (product.farmerId !== farmer.id) {
      throw new ForbiddenException('You can only delete your own products');
    }

    await this.prisma.product.delete({ where: { id } });
    return { success: true, message: 'Product deleted' };
  }
}