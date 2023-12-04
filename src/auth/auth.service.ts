import {
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import { AuthEntity } from './entity/auth.entity';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {}

  async login(email: string, password: string): Promise<AuthEntity> {
    // Fetch an user with the given email
    const user = await this.prisma.user.findUnique({ where: { email } });
    // If no user is found, throw a 404 error
    if (!user) {
      throw new NotFoundException(`No user found for email: ${email}`);
    }

    // Check if the password is valid
    const isPasswordValid = await bcrypt.compare(password, user.password);
    // If password is invalid, throw a 401 error
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid password');
    }

    // Generate a JWT containing the user's ID and return it
    return {
      accessToken: this.jwtService.sign({ userId: user.id }),
    };
  }
}
