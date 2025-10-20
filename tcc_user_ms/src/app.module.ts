import { TerminusModule } from '@nestjs/terminus';
import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { UserService } from './services/user.service';
import { PrismaService } from './services/prisma.service';
import { AuthService } from './services/auth.service';
import { UserController } from './controllers/user.controller';
import { AuthController } from './controllers/auth.controller';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { RabbitMQModule } from '@golevelup/nestjs-rabbitmq';
import { BrokerService } from '@services/broker.service';
import { UserConfigController } from '@controllers/user-config.controller';
import { UserConfigService } from '@services/userConfig.service';
import { SchemaService } from '@services/schema.service';
import { SchemaController } from '@controllers/schema.controller';
import { join } from 'path';
import { readFileSync } from 'fs';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    TerminusModule,
    RabbitMQModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        exchanges: [{ name: 'users_queue', type: 'topic' }],
        uri: configService.get<string>('RABBITMQ_URI'),
        connectionInitOptions: { wait: true },
      }),
      inject: [ConfigService],
    }),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        // publicKey: 
        // privateKey: readFileSync(join(__dirname, '..', 'keys', 'private.pem'), 'utf-8'),
        // publicKey: readFileSync(join(__dirname, '..', 'keys', 'public.pem'), 'utf-8'),
        signOptions: {
          algorithm: 'RS256',
          expiresIn: '15m',
        },
        secretOrPrivateKey: readFileSync(join(__dirname, '..', 'keys', 'private.pem'), 'utf-8'),
        // secretOrKeyProvider: readFileSync(join(__dirname, '..', 'keys', 'public.pem'), 'utf-8'),
        // secret: configService.get<string>('JWT_SECRET'),
        // signOptions: { expiresIn: '1h' },
      }),
      inject: [ConfigService],
    }),
  ],
  controllers: [
    UserController,
    AuthController,
    UserConfigController,
    SchemaController,
  ],
  providers: [
    UserService,
    PrismaService,
    AuthService,
    BrokerService,
    UserConfigService,
    SchemaService,
  ],
  exports: [],
})
export class AppModule {}
