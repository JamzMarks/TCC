
import { Injectable, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from 'generated/prisma';


@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit {

  async onModuleInit() {
    await this.connectWithRetry();
  }
  
  private async connectWithRetry(retries = 5, delay = 5000): Promise<void> {
    try {
      await this.$connect();
    } catch (error) {
      if(retries > 0){
        await new Promise(res => setTimeout(res, delay));
        await this.connectWithRetry(retries - 1, delay);
      }else{
        console.log('Prisma connection failed. Retrying in 5 seconds...', error);
        process.exit(1);
      }
    }
  }
  async checkSchema(): Promise<void> {
    const tables = await this.$queryRaw<{ tablename: string }[]>`
    SELECT tablename
    FROM pg_tables
    WHERE schemaname = current_schema();
  `;
  console.log('Tables in current schema:', tables.map(t => t.tablename));
  const users = await this.user.findMany();
  console.log('Users:', users);
  }
}
