/* eslint-disable prettier/prettier */
import {
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { SafeUser } from '../user/user.service';
import { CreateFarmDto } from './dto/create-farm.dto';
import { UpdateFarmDto } from './dto/update-farm.dto';
import { SearchFarmsDto } from './dto/search-farms.dto';

@Injectable()
export class FarmService {
  constructor(private readonly prisma: PrismaService) {}

  private async getOwnFarmer(user: SafeUser) {
    if (user.role !== 'FARMER') {
      throw new ForbiddenException('Only farmer accounts can manage farms');
    }

    const farmer = await this.prisma.farmer.findUnique({
      where: { userId: user.id },
    });
    if (!farmer) {
      throw new ForbiddenException('Farmer profile not found');
    }

    return farmer;
  }

  async create(user: SafeUser, dto: CreateFarmDto) {
    const farmer = await this.getOwnFarmer(user);

    const existing = await this.prisma.farm.findUnique({
      where: { farmerId: farmer.id },
    });
    if (existing) {
      throw new ConflictException('Farmer already has a farm');
    }

    return this.prisma.farm.create({
      data: { ...dto, farmerId: farmer.id },
    });
  }

  async findAll(query: SearchFarmsDto) {
    const where: Prisma.FarmWhereInput = {};

    if (query.search) {
      where.OR = [
        { name: { contains: query.search, mode: 'insensitive' } },
        { description: { contains: query.search, mode: 'insensitive' } },
      ];
    }
    if (query.country) {
      where.country = { contains: query.country, mode: 'insensitive' };
    }
    if (query.state) {
      where.state = { contains: query.state, mode: 'insensitive' };
    }
    if (query.city) {
      where.city = { contains: query.city, mode: 'insensitive' };
    }

    return this.prisma.farm.findMany({
      where,
      orderBy: { createdAt: 'desc' },
    });
  }

  async findById(id: string) {
    const farm = await this.prisma.farm.findUnique({
      where: { id },
    });
    if (!farm) {
      throw new NotFoundException('Farm not found');
    }
    return farm;
  }

  async update(user: SafeUser, id: string, dto: UpdateFarmDto) {
    const farmer = await this.getOwnFarmer(user);

    const farm = await this.prisma.farm.findUnique({ where: { id } });
    if (!farm) {
      throw new NotFoundException('Farm not found');
    }
    if (farm.farmerId !== farmer.id) {
      throw new ForbiddenException('You can only update your own farm');
    }

    return this.prisma.farm.update({
      where: { id },
      data: dto,
    });
  }
}