"use strict";
// Uncomment these imports to begin using these cool features!
Object.defineProperty(exports, "__esModule", { value: true });
exports.UserController = exports.CredentialsRequestBody = exports.NewUserRequest = void 0;
const tslib_1 = require("tslib");
// import {inject} from '@loopback/core';
// export class UserController {
//   constructor() {}
// }
// Copyright IBM Corp. and LoopBack contributors 2020. All Rights Reserved.
// Node module: @loopback/example-todo-jwt
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT
const authentication_1 = require("@loopback/authentication");
const authentication_jwt_1 = require("@loopback/authentication-jwt");
const core_1 = require("@loopback/core");
const repository_1 = require("@loopback/repository");
const rest_1 = require("@loopback/rest");
const security_1 = require("@loopback/security");
const bcryptjs_1 = require("bcryptjs");
const lodash_1 = tslib_1.__importDefault(require("lodash"));
let NewUserRequest = class NewUserRequest extends authentication_jwt_1.User {
};
tslib_1.__decorate([
    (0, repository_1.property)({
        type: 'string',
        required: true,
    }),
    tslib_1.__metadata("design:type", String)
], NewUserRequest.prototype, "password", void 0);
NewUserRequest = tslib_1.__decorate([
    (0, repository_1.model)()
], NewUserRequest);
exports.NewUserRequest = NewUserRequest;
const CredentialsSchema = {
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
exports.CredentialsRequestBody = {
    description: 'The input of login function',
    required: true,
    content: {
        'application/json': { schema: CredentialsSchema },
    },
};
let UserController = class UserController {
    constructor(jwtService, userService, user, userRepository) {
        this.jwtService = jwtService;
        this.userService = userService;
        this.user = user;
        this.userRepository = userRepository;
    }
    async login(credentials) {
        // ensure the user exists, and the password is correct
        const email = await this.userRepository.find({ where: { email: credentials.email } });
        if (!email) {
            throw new rest_1.HttpErrors.PreconditionFailed('Tai khoan bi sai');
        }
        const user = await this.userService.verifyCredentials(credentials);
        // convert a User object into a UserProfile object (reduced set of properties)
        const userProfile = this.userService.convertToUserProfile(user);
        // create a JSON Web Token based on the user profile
        const token = await this.jwtService.generateToken(userProfile);
        return { token };
        //   N???u t??i kho???n v?? password kh??ng ????ng trong c?? s??? d??? li???u th???
        // Sai:"????ng nh???p kh??ng th??nh c??ng. Vui l??ng ki???m tra t??n ????ng nh???p v?? m???t kh???u."
    }
    async whoAmI(currentUserProfile) {
        return currentUserProfile[security_1.securityId];
    }
    async signUp(newUserRequest) {
        if (newUserRequest.emai.length < 1) {
            throw new rest_1.HttpErrors.PreconditionFailed('Tai khoan chua du so');
        }
        if (newUserRequest.emai.length > 20) {
            throw new rest_1.HttpErrors.PreconditionFailed('Tai khoan thua du so');
        }
        console.log("???? ~ file: user.controller.ts ~ line 160 ~ UserController ~ newUserRequest", newUserRequest);
        const email = await this.userRepository.find({ where: { email: newUserRequest.email }, limit: 1 });
        if (email) {
            throw new rest_1.HttpErrors.BadRequest('Tai khoan da duoc dang ki');
        }
        const password = await (0, bcryptjs_1.hash)(newUserRequest.password, await (0, bcryptjs_1.genSalt)());
        if (newUserRequest.password.length > 8) {
            throw new rest_1.HttpErrors.PreconditionFailed('Mat khau qua ngan');
        }
        const savedUser = await this.userRepository.create(lodash_1.default.omit(newUserRequest, 'password'));
        await this.userRepository.userCredentials(savedUser.id).create({ password });
        return savedUser;
    }
};
tslib_1.__decorate([
    (0, rest_1.post)('/users/login', {
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
    }),
    tslib_1.__param(0, (0, rest_1.requestBody)(exports.CredentialsRequestBody)),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [Object]),
    tslib_1.__metadata("design:returntype", Promise)
], UserController.prototype, "login", null);
tslib_1.__decorate([
    (0, authentication_1.authenticate)('jwt'),
    (0, rest_1.get)('/whoAmI', {
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
    }),
    tslib_1.__param(0, (0, core_1.inject)(security_1.SecurityBindings.USER)),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [Object]),
    tslib_1.__metadata("design:returntype", Promise)
], UserController.prototype, "whoAmI", null);
tslib_1.__decorate([
    (0, rest_1.post)('/signup', {
        responses: {
            '200': {
                description: 'User',
                content: {
                    'application/json': {
                        schema: {
                            'x-ts-type': authentication_jwt_1.User,
                        },
                    },
                },
            },
        },
    }),
    tslib_1.__param(0, (0, rest_1.requestBody)({
        content: {
            'application/json': {
                schema: (0, rest_1.getModelSchemaRef)(NewUserRequest, {
                    title: 'NewUser',
                }),
            },
        },
    })),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [NewUserRequest]),
    tslib_1.__metadata("design:returntype", Promise)
], UserController.prototype, "signUp", null);
UserController = tslib_1.__decorate([
    tslib_1.__param(0, (0, core_1.inject)(authentication_jwt_1.TokenServiceBindings.TOKEN_SERVICE)),
    tslib_1.__param(1, (0, core_1.inject)(authentication_jwt_1.UserServiceBindings.USER_SERVICE)),
    tslib_1.__param(2, (0, core_1.inject)(security_1.SecurityBindings.USER, { optional: true })),
    tslib_1.__param(3, (0, repository_1.repository)(authentication_jwt_1.UserRepository)),
    tslib_1.__metadata("design:paramtypes", [Object, authentication_jwt_1.MyUserService, Object, authentication_jwt_1.UserRepository])
], UserController);
exports.UserController = UserController;
//# sourceMappingURL=user.controller.js.map