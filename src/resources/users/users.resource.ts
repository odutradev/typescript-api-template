import jwt from "jsonwebtoken";
import fs from "fs/promises";

import passwordChangedTemplate from "@email/templates/passwordChanged";
import passwordResetTemplate from "@email/templates/passwordReset";
import validationService from "@utils/services/validation.service"
import passwordResetModel from "@database/model/passwordReset";
import stringService from "@utils/services/string.services";
import objectService from "@utils/services/object.service";
import randomService from "@utils/services/random.service";
import imageService from "@utils/services/image.service";
import dateService from "@utils/services/date.service";
import sendEmail from "@email/functions/sendEmail";
import { hasUser } from "@database/functions/user";
import userModel from "@database/model/user";
import fileStorage from "@storage/file";

import type { ManageRequestBody } from "@middlewares/manageRequest";

type UserModelType = any;

const usersResource = {
    signUp: async ({ data, manageError, createLog }: ManageRequestBody) => {
        try {
            let { email, password, name } = data;
            if (!email || !password) return manageError({ code: "invalid_data" });

            const findUser = await userModel.findOne({ email });
            if (findUser) return manageError({ code: "user_already_exists" });

            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(password, salt);

            const now = dateService.now();

            const newUser: Partial<UserModelType> = {
                email,
                password: hashedPassword,
                name: name ? stringService.filterBadwords(stringService.normalizeString(name)) : undefined,
                firstSignup: now,
                lastUpdate: now,
                status: "loggedIn"
            };

            const createdUser = await userModel.create(newUser);

            await createLog({
                action: "user_signup",
                entity: "user",
                entityID: createdUser._id.toString(),
                userID: createdUser._id.toString(),
                data: {
                    email: createdUser.email,
                    name: createdUser.name,
                    role: createdUser.role
                }
            });

            const template = welcomeTemplate();
            await sendEmail({
                to: createdUser.email as string,
                subject: "Bem-vindo ao AMaisFacil",
                template,
                variables: {
                    userName: createdUser.name || 'Usuário',
                    email: createdUser.email as string,
                    date: dateService.formatDate(now)
                }
            });

            const token = jwt.sign({ id: createdUser._id }, process.env.SECRET || "");
            return { token };		 
        } catch (error) {
            manageError({ code: "internal_error", error });
        }
    },
    signIn: async ({ data, manageError, createLog }: ManageRequestBody) => {
        try {
            let { email, password } = data;
            if (!email || !password) return manageError({ code: "no_credentials_sent" });

            const findUser = await userModel.findOne({ email });
            if (!findUser) return manageError({ code: "user_not_found" });
            
            if (findUser.status !== "loggedIn") return manageError({ code: "user_not_registered" });

            var isPasswordMatch = await bcrypt.compare(password, findUser?.password || "");
            if (!isPasswordMatch) return manageError({ code: "invalid_credentials" });

            await createLog({
                action: "user_signin",
                entity: "user",
                entityID: findUser._id.toString(),
                userID: findUser._id.toString(),
                data: {
                    email: findUser.email,
                    name: findUser.name
                }
            });

            const token = jwt.sign({ id: findUser._id }, process.env.SECRET || "");
            return { token };		 
        } catch (error) {
            manageError({ code: "internal_error", error });
        }
    },
    requestPasswordReset: async ({ data, manageError, createLog }: ManageRequestBody) => {
        try {
            const { email } = data;
            if (!email) return manageError({ code: "invalid_data" });

            const user = await userModel.findOne({ email });
            if (!user) return manageError({ code: "user_not_found" });

            await passwordResetModel.deleteMany({ 
                userID: user._id, 
                verified: false 
            });

            const code = randomService.getRandomNumberInRange(100000, 999999).toString();
            const now = dateService.now();
            const expiresAt = dateService.addMinutes(new Date(), 15);

            const resetRequest = new passwordResetModel({
                userID: user._id,
                email: user.email,
                code,
                verified: false,
                attempts: 0,
                expiresAt,
                createdAt: now
            });

            await resetRequest.save();

            const template = passwordResetTemplate();
            await sendEmail({
                to: user.email as string,
                subject: "Código de redefinição de senha",
                template,
                variables: {
                    code,
                    expirationMinutes: 15
                }
            });

            await createLog({
                action: "system_action",
                entity: "system",
                entityID: resetRequest._id.toString(),
                userID: user._id.toString(),
                data: {
                    description: "Código de redefinição de senha enviado",
                    email: user.email
                }
            });

            return {
                success: true,
                message: "Código enviado para o email",
                expiresIn: 15
            };
        } catch (error) {
            manageError({ code: "internal_error", error });
        }
    },
    verifyResetCode: async ({ data, manageError, createLog }: ManageRequestBody) => {
        try {
            const { email, code } = data;
            if (!email || !code) return manageError({ code: "invalid_data" });

            const user = await userModel.findOne({ email });
            if (!user) return manageError({ code: "user_not_found" });

            const now = dateService.now();

            const resetRequest = await passwordResetModel.findOne({
                userID: user._id,
                verified: false,
                expiresAt: { $gt: now }
            }).sort({ createdAt: -1 });

            if (!resetRequest) return manageError({ code: "invalid_data" });

            if (resetRequest.attempts >= 3) {
                await passwordResetModel.deleteOne({ _id: resetRequest._id });
                return manageError({ code: "invalid_data" });
            }

            if (resetRequest.code !== code) {
                await passwordResetModel.findByIdAndUpdate(
                    resetRequest._id,
                    { $inc: { attempts: 1 } }
                );
                return manageError({ code: "invalid_credentials" });
            }

            await passwordResetModel.findByIdAndUpdate(
                resetRequest._id,
                { verified: true }
            );

            await createLog({
                action: "system_action",
                entity: "system",
                entityID: resetRequest._id.toString(),
                userID: user._id.toString(),
                data: {
                    description: "Código de redefinição verificado",
                    email: user.email
                }
            });

            return {
                success: true,
                message: "Código verificado com sucesso"
            };
        } catch (error) {
            manageError({ code: "internal_error", error });
        }
    },
    resetPassword: async ({ data, manageError, createLog }: ManageRequestBody) => {
        try {
            const { email, code, newPassword } = data;
            if (!email || !code || !newPassword) return manageError({ code: "invalid_data" });

            const user = await userModel.findOne({ email });
            if (!user) return manageError({ code: "user_not_found" });

            const now = dateService.now();

            const resetRequest = await passwordResetModel.findOne({
                userID: user._id,
                code,
                verified: true,
                expiresAt: { $gt: now }
            }).sort({ createdAt: -1 });

            if (!resetRequest) return manageError({ code: "invalid_data" });

            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(newPassword, salt);

            await userModel.findByIdAndUpdate(
                user._id,
                { 
                    password: hashedPassword,
                    lastUpdate: now
                }
            );

            await passwordResetModel.deleteMany({ userID: user._id });

            const template = passwordChangedTemplate();
            await sendEmail({
                to: user.email as string,
                subject: "Senha alterada com sucesso",
                template,
                variables: {
                    userName: user.name || 'Usuário',
                    date: dateService.formatDate(now),
                    time: dateService.formatTime(now)
                }
            });

            await createLog({
                action: "system_action",
                entity: "system",
                entityID: user._id.toString(),
                userID: user._id.toString(),
                data: {
                    description: "Senha redefinida com sucesso",
                    email: user.email
                }
            });

            return {
                success: true,
                message: "Senha alterada com sucesso"
            };
        } catch (error) {
            manageError({ code: "internal_error", error });
        }
    },
    getUser: async ({  manageError, ids }: ManageRequestBody) => {
        try {
            return await hasUser({ _id: ids.userID }, manageError);
        } catch (error) {
            manageError({ code: "internal_error", error });
        }
    },
    updateProfile: async ({  data, manageError, ids, createLog }: ManageRequestBody) => {
        try {
            const { userID } =  ids;
            if (!userID) return manageError({ code: "invalid_params" });

            const userExists = await hasUser({ _id: userID }, manageError);
            if (!userExists) return;

            let filteredUpdatedUser = objectService.getObject(data, ["name", "description", "cpfOrRg"]);

            if (filteredUpdatedUser.name){
                filteredUpdatedUser.name = stringService.filterBadwords(stringService.normalizeString(filteredUpdatedUser.name));
            };

            if (filteredUpdatedUser.description){
                filteredUpdatedUser.description = stringService.filterBadwords(stringService.normalizeString(filteredUpdatedUser.description));
            };

            if (filteredUpdatedUser.cpfOrRg !== undefined) {
                const cleanCpfOrRg = filteredUpdatedUser.cpfOrRg.trim();
                
                if (cleanCpfOrRg && !validationService.validateCPForRG(cleanCpfOrRg)) {
                    return manageError({ code: "author_invalid_cpf_rg" });
                }
                
                filteredUpdatedUser.cpfOrRg = cleanCpfOrRg || null;
            }

            const updatedUser = await userModel.findByIdAndUpdate(
                userID, 
                { $set:{ ...filteredUpdatedUser, lastUpdate: dateService.now() } }, 
                { new: true }
            ).select("-password");

            await createLog({
                action: "user_updated",
                entity: "user",
                entityID: userID,
                userID: userID,
                data: {
                    email: updatedUser?.email,
                    name: updatedUser?.name,
                    updatedFields: Object.keys(filteredUpdatedUser)
                }
            });

            return updatedUser;
        } catch (error) {
            manageError({ code: "internal_error", error });
        }
    },
    updateProfileImage: async ({ manageError, ids, file, createLog }: ManageRequestBody) => {
        try {
            const { userID } = ids;
            if (!userID) return manageError({ code: "invalid_params" });

            if (!file) return manageError({ code: "invalid_data" });

            const user = await hasUser({ _id: userID }, manageError);
            if (!user) return;

            const { mimetype, path } = file;

            if (!mimetype || !path) return manageError({ code: "invalid_data" });

            if (!mimetype.startsWith('image/')) {
                return manageError({ code: "invalid_data" });
            }

            const originalBuffer = await fs.readFile(path);

            const isValidImage = await imageService.validateImage(originalBuffer);
            if (!isValidImage) {
                return manageError({ code: "invalid_data" });
            }

            const { buffer: compressedBuffer, mimeType, originalSize, compressedSize, compressionRatio } = await imageService.compressImage({
                buffer: originalBuffer,
                maxWidth: 1024,
                maxHeight: 1024,
                quality: 80,
                format: "webp"
            });

            const filePath = `users/${userID}/images/profile`;
            
            const { url } = await fileStorage.upload({
                path: filePath,
                buffer: compressedBuffer,
                mimeType,
                isPublic: true
            });

            const updatedUser = await userModel.findByIdAndUpdate(
                userID,
                { 
                    $set: { 
                        'images.profile': url,
                        lastUpdate: dateService.now()
                    }
                },
                { new: true }
            ).select("-password");

            await createLog({
                action: "user_updated",
                entity: "user",
                entityID: userID,
                userID,
                data: {
                    description: "Foto de perfil atualizada com compressão",
                    imageUrl: url,
                    originalSize,
                    compressedSize,
                    compressionRatio: `${compressionRatio.toFixed(2)}%`,
                    savedBytes: originalSize - compressedSize
                }
            });

            return {
                url,
                user: updatedUser,
                compression: {
                    originalSize,
                    compressedSize,
                    compressionRatio: `${compressionRatio.toFixed(2)}%`,
                    savedBytes: originalSize - compressedSize
                }
            };
        } catch (error) {
            manageError({ code: "internal_error", error });
        }
    },
    updateUserById: async ({ data, manageError, params, ids, createLog }: ManageRequestBody) => {
        try {
            const { userID } =  params;
            if (!userID) return manageError({ code: "invalid_params" });

            const userExists = await hasUser({ _id: userID }, manageError);
            if (!userExists) return;

            const filteredUser = objectService.filterObject(data, ["id", "order", "role", "createAt", "password", "_id"]);

            if (filteredUser.name){
                filteredUser.name = stringService.normalizeString(filteredUser.name);
            };

            if (filteredUser.description){
                filteredUser.description = stringService.normalizeString(filteredUser.description);
            };

            if (filteredUser.cpfOrRg !== undefined) {
                const cleanCpfOrRg = filteredUser.cpfOrRg.trim();
                
                if (cleanCpfOrRg && !validationService.validateCPForRG(cleanCpfOrRg)) {
                    return manageError({ code: "author_invalid_cpf_rg" });
                }
                
                filteredUser.cpfOrRg = cleanCpfOrRg || null;
            }

            const updatedUser = await userModel.findByIdAndUpdate(
                userID, 
                { $set:{ ...filteredUser, lastUpdate: dateService.now() } }, 
                { new: true }
            ).select("-password");

            await createLog({
                action: "user_updated",
                entity: "user",
                entityID: userID,
                userID: ids.userID,
                data: {
                    email: updatedUser?.email,
                    name: updatedUser?.name,
                    updatedFields: Object.keys(filteredUser),
                    updatedBy: ids.userID
                },
                additionalInfo: { adminUpdate: true }
            });

            return updatedUser;
        } catch (error) {
            console.log('DEBUG', error)
            manageError({ code: "internal_error", error });
        }
    },
    deleteUserById: async ({ manageError, params, ids, createLog }: ManageRequestBody) => {
        try {
            const { userID } =  params;
            if (!userID) return manageError({ code: "invalid_params" });

            const user = await hasUser({ _id: userID }, manageError);
            if (!user) return;
            
            await userModel.findByIdAndDelete(userID);

            await createLog({
                action: "user_deleted",
                entity: "user",
                entityID: userID,
                userID: ids.userID,
                data: {
                    email: user.email,
                    name: user.name,
                    deletedBy: ids.userID
                }
            });
            
            return {
                delete: true
            };
        } catch (error) {
            manageError({ code: "internal_error", error });
        }
    },
    getUserById: async ({ manageError, params }: ManageRequestBody) => {
        try {
            const { userID } =  params;
            if (!userID) return manageError({ code: "invalid_params" });

           return await hasUser({ _id: userID }, manageError);
        } catch (error) {
            manageError({ code: "internal_error", error });
        }
    },
    getAllUsers: async ({ manageError, querys }: ManageRequestBody) => {
        try {
            const pageNum = Number(querys.page) || 1;
            const limitNum = Number(querys.limit) || 10;
            const returnType = querys.returnType || "full";

            if (pageNum < 1 || limitNum < 1) return manageError({ code: "invalid_params" });
    
            const skip = (pageNum - 1) * limitNum;
            const [users, total] = await Promise.all([
                userModel.find().sort({ createAt: -1 }).skip(skip).limit(limitNum).select('-password'),
                userModel.countDocuments()
            ]);

            const data = returnType == "minimum" ? users.map(x => ({ _id: x._id, name: x.name, email: x.email })): users;
    
            return {
                data,
                meta: {
                    total,
                    page: pageNum,
                    pages: Math.ceil(total / limitNum),
                    limit: limitNum
                }
            };
        } catch (error) {
            manageError({ code: "internal_error", error });
        }
    }
};

export default usersResource;