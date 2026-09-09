-- Whole-Naira (Int) pricing for a Nigerian marketplace.
-- Existing Decimal values are rounded to the nearest Naira.

-- AlterTable
ALTER TABLE "products" ALTER COLUMN "price" TYPE INTEGER USING round("price");

-- AlterTable
ALTER TABLE "orders" ALTER COLUMN "subtotal" TYPE INTEGER USING round("subtotal");
ALTER TABLE "orders" ALTER COLUMN "deliveryFee" TYPE INTEGER USING round("deliveryFee");
ALTER TABLE "orders" ALTER COLUMN "total" TYPE INTEGER USING round("total");

-- AlterTable
ALTER TABLE "order_items" ALTER COLUMN "unitPrice" TYPE INTEGER USING round("unitPrice");
ALTER TABLE "order_items" ALTER COLUMN "totalPrice" TYPE INTEGER USING round("totalPrice");

-- AlterTable
ALTER TABLE "payments" ALTER COLUMN "amount" TYPE INTEGER USING round("amount");