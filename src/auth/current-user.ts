/* eslint-disable prettier/prettier */
import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { SafeUser } from '../user/user.service';

const getCurrentUserByContext = (context: ExecutionContext): SafeUser => {
  return context.switchToHttp().getRequest().user as SafeUser;
};

export const CurrentUser = createParamDecorator(
  (_data: unknown, context: ExecutionContext): SafeUser =>
    getCurrentUserByContext(context),
);