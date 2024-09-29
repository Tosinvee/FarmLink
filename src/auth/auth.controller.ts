/* eslint-disable prettier/prettier */
import { Body, Controller, Post, Request, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignUpDto } from './dtos/signup.dto';
import { LocalAuthGuard } from './guides/local.guard';

@Controller('auth')
export class AuthController {
    constructor(private authService:AuthService){}

    @Post('signup')
    async signup(@Body() signUpDto:SignUpDto){
        return this.authService.signUp(signUpDto)
    }

    @Post('login')
    @UseGuards(LocalAuthGuard)
    async login(@Request() req:any){
        return this.authService.login(req.user)
    }
}
