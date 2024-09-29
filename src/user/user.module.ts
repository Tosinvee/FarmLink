/* eslint-disable prettier/prettier */
import { forwardRef, Module } from '@nestjs/common';
import { UserService } from './user.service';
import { UserController } from './user.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './user.entity';
import { AuthModule } from 'src/auth/auth.module';

@Module({
  providers: [UserService],
  exports:[UserService],
  controllers: [UserController],
  imports:[TypeOrmModule.forFeature([User]),
forwardRef(()=> AuthModule)]
  
})
export class UserModule {}
