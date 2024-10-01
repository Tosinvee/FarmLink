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

    @Post('verify-email')
        async verifyEmail(@Body() dto: {email:string , otp:string}){
           return this.authService.verifyEmail(dto.email, dto.otp) 
        }


    @Post('login')
    @UseGuards(LocalAuthGuard)
    async login(@Request() req:any){
        return this.authService.login(req.user)
    }

    @Post('forgot-password')
    async forgotPassword(@Body() dto:{email:string}){
        return this.authService.forgotPassword(dto.email)
    }

    @Post('verify-otp')
    async verifyPassword(@Body() dto:{email:string, otp:string}){
        return this.authService.verifyOtp(dto.email, dto.otp)
    }

    @Post('reset-password')
    async resetPassword(@Body() dto:{email:string, password:string}){
        return this.authService.resetpassword(dto.email, dto.password)
    }
}
