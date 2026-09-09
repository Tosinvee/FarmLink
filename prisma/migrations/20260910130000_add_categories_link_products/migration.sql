-- CreateTable
CREATE TABLE "categories" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "categories_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "categories_name_key" ON "categories"("name");

-- Seed the two categories needed to backfill existing products
INSERT INTO "categories" ("id", "name", "description", "createdAt", "updatedAt")
VALUES
    (gen_random_uuid(), 'Fresh Produce', 'Vegetables & leafy greens', now(), now()),
    (gen_random_uuid(), 'Dairy & Eggs', 'Milk, eggs & farm dairy', now(), now());

-- AlterTable: add nullable FK, backfill, then tighten
ALTER TABLE "products" ADD COLUMN "categoryId" TEXT;

UPDATE "products" SET "categoryId" = (SELECT "id" FROM "categories" WHERE "name" = 'Fresh Produce') WHERE "category" = 'PRODUCE';
UPDATE "products" SET "categoryId" = (SELECT "id" FROM "categories" WHERE "name" = 'Dairy & Eggs') WHERE "category" = 'DAIRY_EGGS';

-- CreateIndex
CREATE INDEX "products_categoryId_idx" ON "products"("categoryId");

-- AddForeignKey
ALTER TABLE "products" ADD CONSTRAINT "products_categoryId_fkey" FOREIGN KEY ("categoryId") REFERENCES "categories"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- Tighten: no product should remain unmapped here; if any do, the SET NOT NULL below will fail loudly
ALTER TABLE "products" ALTER COLUMN "categoryId" SET NOT NULL;

-- Drop legacy column + index
DROP INDEX "products_category_idx";
ALTER TABLE "products" DROP COLUMN "category";