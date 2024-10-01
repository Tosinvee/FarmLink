/* eslint-disable prettier/prettier */
import { BadRequestException, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { MailService } from 'src/mail/mail.service';
import { User } from 'src/user/user.entity';
import { UserService } from 'src/user/user.service';
import { Repository } from 'typeorm';
import { SignUpDto } from './dtos/signup.dto';
import * as bcrypt from 'bcrypt'
import { Users } from './interface/user';
//import { Users } from './interface/user';
//import passport from 'passport';

@Injectable()
export class AuthService {
    constructor( 
        @InjectRepository(User)
        private userRepository:Repository<User>,
        private userService:UserService,
        private readonly jwtService:JwtService,
        private mailService:MailService,
        private configService:ConfigService
        
    ){}

    


    async sendOtp(email:string): Promise<{message:string}>{
        const otp = this.mailService.generateOtp(100000)
        const formatedOtp = await this.mailService.format(otp, 'OTP Verification')
        const fromAddress = this.configService.get<string>('mail.user')

        const result = await this.mailService.sendMail({
            from:fromAddress,
            to:email,
            subject:'OTP Verification',
            html:formatedOtp
        })

        if (result === "Error sending the email"){
            throw new BadRequestException('Error sending email')
        }
        await this.userRepository.update({email}, {verificationCode:otp, createdAt:new Date()})
      return {message:'Otp sent to email'}}


      async signUp(user:SignUpDto):Promise<{message:string}>{
        const existingUser = await this.userService.findUserByEmail(user.email)
        if(existingUser){
            throw new BadRequestException('User already exit')
        }
        const hashedPassword = await bcrypt.hash(user.password, 10)
        await this.userRepository.save({
            email:user.email,
            password:hashedPassword
        })
        return await this.sendOtp(user.email)
    }

    async verifyEmail(email:string, otp:string):Promise<{message:string, access_token:string}>{
        const user = await this.userService.findUserByEmail(email)
        if(user.verificationCode === otp && this.mailService.verifyOtpTime(user.createdAt)){
            await this.userRepository.update({email},{emailVerified:true})

            const payload = {email:user.email, sub:user.id, roles:[user.role]}
            return {
                message:"Email verified successfully",
                access_token:this.jwtService.sign(payload)
            }
        }
        throw new BadRequestException('Invalid otp')
    }

    async validateUser(email:string, password:string) : Promise<Users>{
        const user = await this.userService.findUserByEmail(email)

        if(user && (await bcrypt.compare(password, user.password ) )){
            if(!user.emailVerified){
                 await this.sendOtp(user.email)
                 throw new BadRequestException('Email not verified')
            }
            return {email: user.email, id:  user.id, roles:  [user.role]}
        }
    }

    async login(user:Users){
        const payload = {email:user.email, sub:user.id, roles:user.roles}
        return {
            access_token:this.jwtService.sign(payload)
        }
    }

    async forgotPassword(email:string): Promise<{message:string}>{
        const user =  await this.userService.findUserByEmail(email)
        if(!user){
            throw new BadRequestException('User does not exit')
        }
        return this.sendOtp(user.email)
    }

    async verifyOtp(email:string, otp:string):Promise<{message:string}>{
        const user = await this.userService.findUserByEmail(email)
        if(!user || user.verificationCode !== otp){
            throw new BadRequestException('Invalid email or Otp')
        }
        await this.userRepository.update({email}, {verificationCode:null})
        return{
            message:'Otp verified sucessfully, you can now set your password'
        }
    }

    async resetpassword(email:string, newPassword:string):Promise<{message:string}>{
        const user = await this.userService.findUserByEmail(email)
        if(!user){
            throw new BadRequestException('User does not exist')
        }
        const hashedPassword = await bcrypt.hash(newPassword, 10)
        await this.userRepository.update({email}, {password:hashedPassword})
        return{
            message:'password reset successfully'
        }
    }
         
    }


