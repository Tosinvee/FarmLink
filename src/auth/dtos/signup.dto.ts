/* eslint-disable prettier/prettier */
import { IsEmail, IsNotEmpty, IsString, MinLength } from "class-validator";

export class SignUpDto{
    @IsEmail()
    @IsNotEmpty()
    email:string;

    @IsString()
    @MinLength(8)
    @IsNotEmpty()
    password:string;
}