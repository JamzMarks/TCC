import {
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaService } from './prisma.service';
import { LoginDto } from 'src/dto/login.dto';
import { compare } from 'bcrypt';
import { hashPassword } from '@utils/HashPassword';
import { JwtService } from '@nestjs/jwt';
import { PayloadDto } from '@dtos/auth/payload.dto';
import { Response } from 'express';
import { readFileSync } from 'fs';
import { join } from 'path';
import { UserDto } from '@dtos/user.dto';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {}

  async signin(dto: LoginDto, res: Response): Promise<any> {
    const normalizedEmail = dto.email.trim().toLowerCase();
    const user = await this.prisma.user.findUnique({
      where: { email: normalizedEmail },
    });
    if (!user || !(await compare(dto.password, user.password))) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const payload = this.buildTokenPayload(user);
    const { access_token, refresh_token } = await this.generateTokens(payload);

    const isProd = process.env.NODE_ENV === 'production';
    console.log(isProd ? 'Production environment detected. Setting secure cookies.' : 'Development environment detected. Setting non-secure cookies.');
    res.cookie('access_token', access_token, {
      httpOnly: true,
      secure: isProd, 
      sameSite: isProd ? 'none' : 'lax',
      domain: isProd ? '.tailfox.cloud' : 'localhost',
      path: '/',
      maxAge: 15 * 60 * 1000,
    });

    res.cookie('refresh_token', refresh_token, {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? 'none' : 'lax',
      domain: isProd ? '.tailfox.cloud' : 'localhost',
      path: '/',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    

    return {
      user: payload,
    };
  }

  async me(res: Response): Promise<UserDto> {
    const access_token = res.req.cookies['access_token'];
    if (!access_token) throw new UnauthorizedException('No access token');

    const isValid = await this.validateToken(access_token);
    if (!isValid) {
      throw new UnauthorizedException('Invalid access token');
    }
    const decoded = await this.jwtService.verifyAsync(access_token, {
      secret: process.env.JWT_SECRET,
    });
    const user = await this.prisma.user.findUnique({
      where: { id: decoded.sub },
    });
    if (!user) {
      console.log('o erro ocorreu aqui');
      throw new UnauthorizedException('User not found');
    }
    const userRes = {
      id: user.id,
      firstName: user.firstName,
      lastName: user.lastName,
      role: user.role,
      avatar: user.avatar,
      email: user.email,
    };
    return userRes;
  }

  async updateUserPassword(
    id: string,
    newPassword: string,
    confirmationPassword: string,
  ): Promise<{ message: string }> {
    const user = await this.prisma.user.findUnique({ where: { id } });
    if (!user) throw new NotFoundException('User not found');

    const isMatch = await compare(confirmationPassword, user.password);
    if (!isMatch) {
      throw new UnauthorizedException('Current password incorrect.');
    }

    const hashedPassword = await hashPassword(newPassword);

    await this.prisma.user.update({
      where: { id },
      data: { password: hashedPassword },
    });

    return { message: 'Password updated successfully' };
  }

  async refreshAccessToken(refresh_token: string): Promise<string> {
    if (!refresh_token) {
      throw new UnauthorizedException('No refresh token provided');
    }
    const isValid = await this.validateRefreshToken(refresh_token);
    if (!isValid) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const decoded = await this.jwtService.verifyAsync(refresh_token);

    const user = await this.prisma.user.findUnique({
      where: { id: decoded.sub },
    });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    const payload = this.buildTokenPayload(user);
    const { access_token } = await this.generateTokens(payload);

    return access_token;
  }

  private buildTokenPayload(user: any): PayloadDto {
    const payload = {
      sub: user.id,
      email: user.email,
      role: user.role,
      name: user.firstName + ' ' + user.lastName,
    };
    return payload;
  }

  async generateTokens(payload: PayloadDto) {
    const privateKey = readFileSync(
      join(__dirname, '../..', 'keys', 'private.pem'),
      'utf-8',
    );

    const access_token = await this.jwtService.signAsync(payload, {
      algorithm: 'RS256',
      privateKey,
      // secret: process.env.JWT_SECRET,
      expiresIn: '15m',
    });
    const refresh_token = await this.jwtService.signAsync(
      { sub: payload.sub },
      {
        algorithm: 'RS256',
        privateKey,
        // secret: process.env.JWT_REFRESH_SECRET,
        expiresIn: '7d',
      },
    );
    return { access_token, refresh_token };
  }

  private async validateToken(accessToken: string): Promise<Boolean> {
    const publicKey = readFileSync(
      join(__dirname, '../..', 'keys', 'public.pem'),
      'utf-8',
    );
    try {
      await this.jwtService.verifyAsync(accessToken, {
        publicKey, 
        algorithms: ['RS256'],
      });
      return true;
    } catch {
      return false;
    }
  }

  private async validateRefreshToken(refreshToken: string): Promise<Boolean> {
    const publicKey = readFileSync(
      join(__dirname, '../..', 'keys', 'public.pem'),
      'utf-8',
    );
    try {
      await this.jwtService.verifyAsync(refreshToken, {
        publicKey, 
        algorithms: ['RS256'],
      });
      return true;
    } catch {
      return false;
    }
  }
}
