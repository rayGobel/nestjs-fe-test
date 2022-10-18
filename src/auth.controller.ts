import {
  Controller,
  Post,
  Req,
  Res,
  HttpStatus,
  HttpException,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}
  @Post('email-register')
  emailRegister(@Req() request: Request, @Res() response: Response) {
    const { email, password } = request.body;

    if (!email || !password) {
      throw new HttpException(
        {
          status: HttpStatus.BAD_REQUEST,
          error: 'No username / password provided',
        },
        HttpStatus.BAD_REQUEST,
      );
    }

    try {
      const credentials = { email, password };
      const newSession = this.authService.registerUser(credentials);

      return response.status(HttpStatus.CREATED).send(newSession);
    } catch (err) {
      const message = err.message;
      throw new HttpException(
        {
          status: HttpStatus.INTERNAL_SERVER_ERROR,
          error: `Server Error: ${message}`,
        },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Post('email-login')
  emailLogin(@Req() request: Request): string {
    const { email, password } = request.body;

    if (!email || !password) {
      throw new HttpException(
        {
          status: HttpStatus.BAD_REQUEST,
          error: 'No email / password provided',
        },
        HttpStatus.BAD_REQUEST,
      );
    }

    try {
      const session = this.authService.tryLogin(email, password);

      if (!session) {
        throw new HttpException(
          {
            status: HttpStatus.BAD_REQUEST,
            error: 'Invalid email / password combination',
          },
          HttpStatus.BAD_REQUEST,
        );
      }

      return JSON.stringify(session);
    } catch (err) {
      const message = err.message;
      throw new HttpException(
        {
          status: HttpStatus.INTERNAL_SERVER_ERROR,
          error: `Server Error: ${message}`,
        },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }
}
