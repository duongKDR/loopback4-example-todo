// Uncomment these imports to begin using these cool features!

// import {inject} from '@loopback/core';


// export class UserController {
//   constructor() {}
// }
// Copyright IBM Corp. and LoopBack contributors 2020. All Rights Reserved.
// Node module: @loopback/example-todo-jwt
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT

import { authenticate, TokenService } from '@loopback/authentication';
import {
  Credentials,
  MyUserService,
  TokenServiceBindings,
  User,
  UserCredentials,
  UserRepository,
  UserServiceBindings,
} from '@loopback/authentication-jwt';
import { inject } from '@loopback/core';
import { model, property, repository } from '@loopback/repository';
import {
  get,
  getModelSchemaRef,
  HttpErrors,
  post,
  requestBody,
  SchemaObject,
} from '@loopback/rest';
import { SecurityBindings, securityId, UserProfile } from '@loopback/security';
import { genSalt, hash } from 'bcryptjs';
import _ from 'lodash';
import { ifError } from 'should';

@model()
export class NewUserRequest extends User {
  @property({
    type: 'string',
    required: true,
  })
  password: string;
}

const CredentialsSchema: SchemaObject = {
  type: 'object',
  required: ['email', 'password'],
  properties: {
    email: {
      type: 'string',
      format: 'email',
    },
    password: {
      type: 'string',
      minLength: 8,
    },
  },
};

export const CredentialsRequestBody = {
  description: 'The input of login function',
  required: true,
  content: {
    'application/json': { schema: CredentialsSchema },
  },
};

export class UserController {
  constructor(
    @inject(TokenServiceBindings.TOKEN_SERVICE)
    public jwtService: TokenService,
    @inject(UserServiceBindings.USER_SERVICE)
    public userService: MyUserService,
    @inject(SecurityBindings.USER, { optional: true })
    public user: UserProfile,
    @repository(UserRepository) protected userRepository: UserRepository,
  ) { }

  @post('/users/login', {
    responses: {
      '200': {
        description: 'Token',
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: {
                token: {
                  type: 'string',
                },
              },
            },
          },
        },
      },
    },
  })
  async login(
    @requestBody(CredentialsRequestBody) credentials: Credentials,
  ): Promise<{ token: string }> {
    // ensure the user exists, and the password is correct
    const email = await this.userRepository.find({ where: { email: credentials.email } })
    if (!email) {
      throw new HttpErrors.PreconditionFailed('Tai khoan bi sai');
    }

    const user = await this.userService.verifyCredentials(credentials);
    // convert a User object into a UserProfile object (reduced set of properties)
    const userProfile = this.userService.convertToUserProfile(user);

    // create a JSON Web Token based on the user profile
    const token = await this.jwtService.generateToken(userProfile);
    return { token };

    //   Nếu tài khoản và password không đúng trong cơ sở dữ liệu thị
    // Sai:"Đăng nhập không thành công. Vui lòng kiểm tra tên đăng nhập và mật khẩu."

  }

  @authenticate('jwt')
  @get('/whoAmI', {

    responses: {
      '200': {
        description: 'Return current user',
        content: {
          'application/json': {
            schema: {
              type: 'string',
            },
          },
        },
      },
    },
  })
  async whoAmI(
    @inject(SecurityBindings.USER)
    currentUserProfile: UserProfile,
  ): Promise<string> {
    return currentUserProfile[securityId];
  }

  @post('/signup', {
    responses: {
      '200': {
        description: 'User',
        content: {
          'application/json': {
            schema: {
              'x-ts-type': User,
            },
          },
        },
      },
    },
  })
  async signUp(
    @requestBody({
      content: {
        'application/json': {
          schema: getModelSchemaRef(NewUserRequest, {
            title: 'NewUser',
          }),
        },
      },
    })
    newUserRequest: NewUserRequest,
  ): Promise<User> {
    if (newUserRequest.emai.length < 1) {
      throw new HttpErrors.PreconditionFailed('Tai khoan chua du so');
    }

    if (newUserRequest.emai.length > 20) {
      throw new HttpErrors.PreconditionFailed('Tai khoan thua du so');
    }


    console.log("🚀 ~ file: user.controller.ts ~ line 160 ~ UserController ~ newUserRequest", newUserRequest)
    const email = await this.userRepository.find({ where: { email: newUserRequest.email }, limit: 1 });
    if (email) {
      throw new HttpErrors.BadRequest('Tai khoan da duoc dang ki');
    }


    const password = await hash(newUserRequest.password, await genSalt());
    if (newUserRequest.password.length > 8) {
      throw new HttpErrors.PreconditionFailed('Mat khau qua ngan');

    }
    const savedUser = await this.userRepository.create(
      _.omit(newUserRequest, 'password'),
    );


    await this.userRepository.userCredentials(savedUser.id).create({ password });

    return savedUser;
  }
}
