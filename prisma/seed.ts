/* eslint-disable prettier/prettier */
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

const categories = [
  { name: 'Fresh Produce', description: 'Vegetables, leafy greens & salad crops' },
  { name: 'Fruits', description: 'Seasonal fruits from local farms' },
  { name: 'Grains', description: 'Rice, maize, millet & sorghum' },
  { name: 'Tubers', description: 'Yam, cassava, potatoes & cocoyam' },
  { name: 'Legumes', description: 'Beans, groundnuts & soybeans' },
  { name: 'Livestock', description: 'Cattle, goats, sheep & poultry' },
  { name: 'Dairy & Eggs', description: 'Milk, eggs & farm dairy products' },
  { name: 'Fish & Seafood', description: 'Fresh catch & farmed fish' },
  { name: 'Herbs & Spices', description: 'Pepper, ginger, garlic & herbs' },
  { name: 'Nuts & Seeds', description: 'Cashew, almonds, sesame & more' },
  { name: 'Honey', description: 'Raw honey & bee products' },
  { name: 'Farm Oils', description: 'Palm oil, groundnut oil & more' },
];

async function main() {
  for (const category of categories) {
    await prisma.category.upsert({
      where: { name: category.name },
      update: { description: category.description },
      create: category,
    });
  }
  console.log(`Seeded ${categories.length} categories`);
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());