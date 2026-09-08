/* eslint-disable prettier/prettier */
import { PrismaClient, Role } from '@prisma/client';
import * as bcrypt from 'bcrypt';

const prisma = new PrismaClient();

async function main() {
  const password = await bcrypt.hash('Admin@1234', 10);

  await prisma.user.upsert({
    where: { email: 'admin@farmlink.test' },
    update: {},
    create: {
      email: 'admin@farmlink.test',
      password,
      firstName: 'FarmLink',
      lastName: 'Admin',
      role: Role.ADMIN,
      emailVerified: true,
      cart: { create: {} },
    },
  });

  const farmerUser = await prisma.user.upsert({
    where: { email: 'farmer@farmlink.test' },
    update: {},
    create: {
      email: 'farmer@farmlink.test',
      password,
      firstName: 'Mary',
      lastName: 'Okafor',
      role: Role.FARMER,
      emailVerified: true,
      cart: { create: {} },
      farmer: {
        create: {
          displayName: 'Okafor Fresh Farms',
          description: 'Organic vegetables and fresh produce from Rivers State.',
          location: 'Port Harcourt, Rivers State',
          phone: '+2348000000001',
          farm: {
            create: {
              name: 'Okafor Fresh Farm',
              location: 'Ikwerre, Rivers State',
              acreage: 4.5,
            },
          },
        },
      },
    },
  });

  await prisma.user.upsert({
    where: { email: 'consumer@farmlink.test' },
    update: {},
    create: {
      email: 'consumer@farmlink.test',
      password,
      firstName: 'Chidi',
      lastName: 'Okeke',
      role: Role.CONSUMER,
      emailVerified: true,
      cart: { create: {} },
    },
  });

  const farmer = await prisma.farmer.findUnique({
    where: { userId: farmerUser.id },
    include: { farm: true },
  });

  if (farmer?.farm) {
    await prisma.product.createMany({
      data: [
        {
          farmerId: farmer.id,
          farmId: farmer.farm.id,
          name: 'Fresh Tomatoes',
          description: 'Sun-ripened organic tomatoes.',
          category: 'PRODUCE',
          price: 3.5,
          quantity: 200,
          unit: 'kg',
        },
        {
          farmerId: farmer.id,
          farmId: farmer.farm.id,
          name: 'Organic Plantain',
          description: 'Locally grown sweet plantain.',
          category: 'PRODUCE',
          price: 2.2,
          quantity: 300,
          unit: 'kg',
        },
        {
          farmerId: farmer.id,
          farmId: farmer.farm.id,
          name: 'Free-Range Eggs (Crate)',
          description: 'Fresh eggs from free-range chickens.',
          category: 'DAIRY_EGGS',
          price: 12,
          quantity: 80,
          unit: 'crate',
        },
      ],
    });
  }

  console.log('Seed complete:');
  console.log('  admin@farmlink.test   (ADMIN)');
  console.log('  farmer@farmlink.test  (FARMER)');
  console.log('  consumer@farmlink.test (CONSUMER)');
  console.log('Password for all seeded users: Admin@1234');
}

main()
  .catch((error) => {
    console.error(error);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });