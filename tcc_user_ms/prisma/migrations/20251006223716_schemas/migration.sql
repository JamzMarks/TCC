-- CreateSchema
CREATE SCHEMA IF NOT EXISTS "users";

-- CreateEnum
CREATE TYPE "users"."Roles" AS ENUM ('USER', 'ADMIN', 'ENGINEER', 'AUDITOR');

-- CreateEnum
CREATE TYPE "users"."Theme" AS ENUM ('LIGHT', 'DARK');

-- CreateEnum
CREATE TYPE "users"."Language" AS ENUM ('PTBR', 'EN', 'ES');

-- CreateTable
CREATE TABLE "users"."User" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "firstName" TEXT NOT NULL,
    "lastName" TEXT NOT NULL,
    "password" TEXT NOT NULL,
    "role" "users"."Roles" NOT NULL DEFAULT 'USER',
    "avatar" TEXT,
    "isActive" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "users"."UserConfig" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "language" "users"."Language" NOT NULL DEFAULT 'EN',
    "theme" "users"."Theme" NOT NULL DEFAULT 'LIGHT',

    CONSTRAINT "UserConfig_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "users"."User"("email");

-- CreateIndex
CREATE UNIQUE INDEX "UserConfig_userId_key" ON "users"."UserConfig"("userId");

-- AddForeignKey
ALTER TABLE "users"."UserConfig" ADD CONSTRAINT "UserConfig_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"."User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
