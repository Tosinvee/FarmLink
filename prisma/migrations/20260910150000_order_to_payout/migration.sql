-- Order → Payment → Payout flow (single-farmer orders, 8% platform commission).

-- CreateEnum
CREATE TYPE "PayoutStatus" AS ENUM ('PENDING', 'PROCESSING', 'PAID', 'FAILED');

-- AlterEnum (additive)
ALTER TYPE "OrderStatus" ADD VALUE 'PENDING_PAYMENT';
ALTER TYPE "PaymentStatus" ADD VALUE 'PROCESSING';

-- AlterTable (orders): link each order to its single farmer
ALTER TABLE "orders" ADD COLUMN     "farmerId" TEXT;

-- Backfill from order items → products, then drop any orphaned test orders
UPDATE "orders" o
SET "farmerId" = sub."farmerId"
FROM (
  SELECT "oi"."orderId" AS "orderId", MIN("p"."farmerId") AS "farmerId"
  FROM "order_items" "oi"
  LEFT JOIN "products" "p" ON "p"."id" = "oi"."productId"
  WHERE "oi"."productId" IS NOT NULL
  GROUP BY "oi"."orderId"
) sub
WHERE o."id" = sub."orderId";

DELETE FROM "orders" WHERE "farmerId" IS NULL;

ALTER TABLE "orders" ALTER COLUMN "farmerId" SET NOT NULL;

-- AddForeignKey
ALTER TABLE "orders" ADD CONSTRAINT "orders_farmerId_fkey" FOREIGN KEY ("farmerId") REFERENCES "farmers"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- CreateIndex
CREATE INDEX "orders_farmerId_idx" ON "orders"("farmerId");

-- AlterTable (payments)
ALTER TABLE "payments"
ADD COLUMN     "provider" TEXT NOT NULL DEFAULT 'paystack',
ADD COLUMN     "providerReference" TEXT,
ADD COLUMN     "authorizationUrl" TEXT,
ADD COLUMN     "accessCode" TEXT,
ADD COLUMN     "gatewayResponse" JSONB;

-- CreateTable
CREATE TABLE "platform_settings" (
    "id" INTEGER NOT NULL DEFAULT 1,
    "commissionRatePct" DOUBLE PRECISION NOT NULL DEFAULT 8,
    "minimumPayoutAmount" INTEGER NOT NULL DEFAULT 5000,

    CONSTRAINT "platform_settings_pkey" PRIMARY KEY ("id")
);

-- Seed the single platform settings row
INSERT INTO "platform_settings" ("id", "commissionRatePct", "minimumPayoutAmount")
VALUES (1, 8, 5000)
ON CONFLICT ("id") DO NOTHING;

-- CreateTable
CREATE TABLE "farmer_payout_accounts" (
    "id" TEXT NOT NULL,
    "farmerId" TEXT NOT NULL,
    "bankName" TEXT NOT NULL,
    "accountName" TEXT NOT NULL,
    "accountNumber" TEXT NOT NULL,
    "bankCode" TEXT,
    "isDefault" BOOLEAN NOT NULL DEFAULT true,
    "isVerified" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "farmer_payout_accounts_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "farmer_earnings" (
    "id" TEXT NOT NULL,
    "farmerId" TEXT NOT NULL,
    "orderId" TEXT NOT NULL,
    "grossAmount" INTEGER NOT NULL,
    "platformCommission" INTEGER NOT NULL,
    "netAmount" INTEGER NOT NULL,
    "currency" TEXT NOT NULL DEFAULT 'NGN',
    "isPaidOut" BOOLEAN NOT NULL DEFAULT false,
    "earnedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "farmer_earnings_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "farmer_payouts" (
    "id" TEXT NOT NULL,
    "farmerId" TEXT NOT NULL,
    "payoutAccountId" TEXT NOT NULL,
    "amount" INTEGER NOT NULL,
    "status" "PayoutStatus" NOT NULL DEFAULT 'PENDING',
    "reference" TEXT NOT NULL,
    "failureReason" TEXT,
    "processedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "farmer_payouts_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "farmer_payout_accounts_farmerId_key" ON "farmer_payout_accounts"("farmerId");

-- CreateIndex
CREATE UNIQUE INDEX "farmer_earnings_farmerId_orderId_key" ON "farmer_earnings"("farmerId", "orderId");

-- CreateIndex
CREATE INDEX "farmer_earnings_farmerId_idx" ON "farmer_earnings"("farmerId");

-- CreateIndex
CREATE UNIQUE INDEX "farmer_payouts_reference_key" ON "farmer_payouts"("reference");

-- CreateIndex
CREATE INDEX "farmer_payouts_farmerId_idx" ON "farmer_payouts"("farmerId");

-- AddForeignKey
ALTER TABLE "farmer_payout_accounts" ADD CONSTRAINT "farmer_payout_accounts_farmerId_fkey" FOREIGN KEY ("farmerId") REFERENCES "farmers"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "farmer_earnings" ADD CONSTRAINT "farmer_earnings_farmerId_fkey" FOREIGN KEY ("farmerId") REFERENCES "farmers"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "farmer_earnings" ADD CONSTRAINT "farmer_earnings_orderId_fkey" FOREIGN KEY ("orderId") REFERENCES "orders"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "farmer_payouts" ADD CONSTRAINT "farmer_payouts_farmerId_fkey" FOREIGN KEY ("farmerId") REFERENCES "farmers"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "farmer_payouts" ADD CONSTRAINT "farmer_payouts_payoutAccountId_fkey" FOREIGN KEY ("payoutAccountId") REFERENCES "farmer_payout_accounts"("id") ON DELETE RESTRICT ON UPDATE CASCADE;