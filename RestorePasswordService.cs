using IdentityServer4.Configuration;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Nbt.Contacts.Contract.Constants;
using Nbt.Contacts.Contract.Dto;
using Nbt.Identity.Application.Exceptions;
using Nbt.Identity.Application.Services.Contacts;
using Nbt.Identity.Contract.Entities;
using Nbt.Identity.DataAccess.Contexts;
using Nbt.Identity.Domain.Constants;
using Nbt.Identity.Domain.Dto;
using Nbt.Identity.Domain.Options;
using Nbt.ManageUser.Contract.Dto;
using System.Text.RegularExpressions;
using System.Web;

namespace Nbt.Identity.Application.Services.RestorePassword;

public class RestorePasswordService : IRestorePasswordService
{
    private readonly ApplicationDbContext _context;
    private readonly IContactsService _contactsService;
    private readonly UserManager<UserIdentity> _userManager;
    private readonly ILogger<RestorePasswordService> _logger;
    private readonly IRestorePasswordSendStrategy _restorePasswordSendStrategy;
    private readonly IdentityServerOptions _identityServerOptions;
    private readonly PasswordExpirationLifetimeOptions _passwordExpirationOptions;
    private readonly IdentityOptions _identityOptions;
    private readonly SupervisorOptions _supervisorOptions;

    public RestorePasswordService(
        ApplicationDbContext context,
        IContactsService contactsService,
        UserManager<UserIdentity> userManager,
        ILogger<RestorePasswordService> logger,
        IRestorePasswordSendStrategy restorerPasswordSendStrategy,
        IOptions<IdentityServerOptions> identityServerOptions,
        IOptions<PasswordExpirationLifetimeOptions> passwordExpirationOptions,
        IOptions<SupervisorOptions> supervisorOptions,
        IOptions<IdentityOptions> identityOptions)
    {
        _context = context;
        _contactsService = contactsService;
        _userManager = userManager;
        _logger = logger;
        _restorePasswordSendStrategy = restorerPasswordSendStrategy;
        _identityServerOptions = identityServerOptions.Value;
        _passwordExpirationOptions = passwordExpirationOptions.Value;
        _supervisorOptions = supervisorOptions.Value;
        _identityOptions = identityOptions.Value;
    }

    public async Task<string> GenerateRestorePasswordLinkAsync(long userId, string returnUrl, string restoreEndpoint = null)
    {
        var user = await _userManager.FindByIdAsync(userId.ToString());
        var passwordResetToken = await _userManager.GeneratePasswordResetTokenAsync(user);
        restoreEndpoint ??= "/Auth/ValidateRestorePasswordToken";
        var passwordLink = $"{restoreEndpoint}?userId={user.Id}&token={HttpUtility.UrlEncode(passwordResetToken)}";
        var resultUri = new Uri(new Uri(_identityServerOptions.PublicOrigin), passwordLink);
        var resultPasswordLink = resultUri.AbsoluteUri;
        return string.IsNullOrEmpty(returnUrl)
            ? resultPasswordLink
            : resultPasswordLink + $"&returnUrl={Uri.EscapeDataString(returnUrl)}";
    }

    public async Task<ValidateRestorePasswordTokenResult> ValidateRestorePasswordTokenAsync(long userId, string token)
    {
        var user = await _userManager.FindByIdAsync(userId.ToString());
        var isValid = await _userManager.VerifyUserTokenAsync(user, _userManager.Options.Tokens.PasswordResetTokenProvider,
            UserManager<UserIdentity>.ResetPasswordTokenPurpose, token);

        return new ValidateRestorePasswordTokenResult
        {
            IsValid = isValid,
            ErrorMessage = !isValid
                ? $"Токен восстановления пароля пользователя {user.UserName} не прошел проверку"
                : null,
            IsSupervisorUser = user.UserName.ToLower() == SupervisorConstants.SupervisorUserName
        };
    }

    public async Task<string> RestorePasswordAsync(string loginOrEmail, string returnUrl, string restoreEndpoint = null)
    {
        try
        {
            if (string.IsNullOrEmpty(loginOrEmail))
                return RestorePasswordConstants.EmptyLoginOrEmailFieldRestorePasswordErrorMessage;

            var userInfoResult = await GetUserInfoAsync(loginOrEmail);
            if (!string.IsNullOrEmpty(userInfoResult.ErrorMessage))
                return userInfoResult.ErrorMessage;

            var link = await GenerateRestorePasswordLinkAsync(userInfoResult.User.Id, returnUrl, restoreEndpoint);
            var sendRecoverPasswordError = await _restorePasswordSendStrategy.SendRestorePasswordLinkAsync(link, userInfoResult.Email);
            if (!string.IsNullOrEmpty(sendRecoverPasswordError))
            {
                _logger.LogError($"Операция отправки ссылки на восстановление завершилась с ошибкой: {sendRecoverPasswordError}");
                return sendRecoverPasswordError;
            }

            return null;
        }
        catch (Exception ex)
        {
            var exMessage = "Произошла ошибка при обработке запроса на восстановление пароля пользователя";
            _logger.LogError(exMessage, ex);
            return exMessage;
        }
    }

    public async Task<UserInfoResult> RestoreSupervisorPasswordAsync(UserIdentity supervisorUser)
    {
        if (supervisorUser == null)
        {
            throw new ArgumentNullException(nameof(supervisorUser));
        }

        try
        {
            // генерация пароля
            var password = GeneratePassword();
            // запись пароля в файл с секретами k8s
            await File.WriteAllTextAsync(_supervisorOptions.PasswordFilePath, password.Value);
            // изменение пароля Супервизора по токену сброса пароля
            var token = await _userManager.GeneratePasswordResetTokenAsync(supervisorUser);
            await _userManager.ResetPasswordAsync(supervisorUser, token, password.Value);
            supervisorUser.NeedChangePassword = false;
            supervisorUser.PasswordExpirationDate = null;
            await _userManager.UpdateAsync(supervisorUser);
            return new UserInfoResult
            {
                ErrorMessage = null
            };
        }
        catch (Exception ex)
        {
            return LogErrorAndCreateResult(
                $"Произошла ошибка при обработке запроса на восстановление пароля пользователя Супервизора: {ex.Message}");
        }
    }

    public PasswordDto GeneratePassword()
    {
        var consonantChars = GeneratePasswordConstants.AllowedConsonantChars;
        var vowelChars = GeneratePasswordConstants.AllowedVowelChars;
        var digitChars = GeneratePasswordConstants.AllowedDigitChars;
        var symbolChars = GeneratePasswordConstants.AllowedSymbolChars;

        bool requireDigit = _identityOptions.Password.RequireDigit;
        bool requireNonAlphanumeric = _identityOptions.Password.RequireNonAlphanumeric;
        bool requireLowercase = _identityOptions.Password.RequireLowercase;
        bool requireUppercase = _identityOptions.Password.RequireUppercase;
        int length = _identityOptions.Password.RequiredLength;

        Random random = new();

        string password = string.Empty;
        int attempts = 0;

        do
        {
            List<char> chars = new();

            int digitPlace = random.Next(length - 2) + 1;
            int symbolPlace = digitPlace;

            while (symbolPlace == digitPlace)
                symbolPlace = random.Next(length - 2) + 1;

            // Сгенерируем пароль чередуя гласные и согласные буквы, чтобы было удобно его читать
            for (int i = 0; i < length; i++)
            {
                if (requireDigit && i == digitPlace)
                    chars.Add(digitChars[random.Next(digitChars.Length)]);
                else if (requireNonAlphanumeric && i == symbolPlace)
                    chars.Add(symbolChars[random.Next(symbolChars.Length)]);
                else if (i % 2 == 0)
                    chars.Add(consonantChars[random.Next(consonantChars.Length)]);
                else
                    chars.Add(vowelChars[random.Next(vowelChars.Length)]);
            }

            password = new string(chars.ToArray());

            if (attempts++ > 100)
                throw new NbtPlatformGeneratePasswordException(@$"Не удалось сгенерировать пароль, соответствующий требованиям: 
                    Длина: {length};
                    Наличие цифр: {requireDigit};
                    Наличие символов нижнего регистра: {requireLowercase};
                    Наличие символов верхнего регистра: {requireUppercase};
                    Наличие спецсимволов: {requireNonAlphanumeric}.");
        }
        while ((requireUppercase && !password.Any(char.IsUpper)) || (requireLowercase && !password.Any(char.IsLower)));

        return new PasswordDto()
        {
            Value = password,
            LifetimeInMinutes = _passwordExpirationOptions.LifetimeInMinutes,
        };
    }

    private async Task<UserInfoResult> GetUserInfoAsync(string loginOrEmail)
    {
        var userInfoResult = IsEmail(loginOrEmail)
            ? await GetUserInfoByEmailAsync(loginOrEmail)
            : await GetUserInfoByLogin(loginOrEmail);

        if (userInfoResult.User != null && IsBlocked(userInfoResult.User))
            return LogErrorAndCreateResult($"Пользователь {userInfoResult.User.Id} заблокирован до {userInfoResult.User.LockoutEnd}",
                AccountOptions.UserWithCurrentLoginOrEmailIsLockedErrorMessage);

        return userInfoResult;
    }


    private async Task<UserInfoResult> GetUserInfoByEmailAsync(string email)
    {
        var attribute = new SearchContactAttribute
        {
            FieldName = ContactsConstants.EmailFieldName,
            FieldValue = email,
            IgnoreCase = true
        };

        var contacts = await _contactsService.GetContactsByAttributeAsync(attribute);
        if (contacts == null || contacts.Length == 0)
            return LogErrorAndCreateResult($"Не найдены контакты по атрибуту {attribute.FieldName} = {attribute.FieldValue}");

        if (contacts.Length > 1)
            return LogErrorAndCreateResult($"По атрибуту {attribute.FieldName} = {attribute.FieldValue} найден более чем 1 контакт({contacts.Length})",
                AccountOptions.PasswordRecoveryIsNotAvailableErrorMessage);

        var contactId = contacts.First().Id;
        var usersByContactId = await _context.Users.Where(x => !x.Deleted && x.ContactId == contactId).ToArrayAsync();
        if (usersByContactId.Length != 1)
            return LogErrorAndCreateResult($"По идентификатору контакта({contactId}) найдено {usersByContactId.Length} пользователей");

        return new UserInfoResult
        {
            User = usersByContactId.First(),
            Email = email
        };
    }

    private async Task<UserInfoResult> GetUserInfoByLogin(string login)
    {
        var userByLogin = await _userManager.FindByNameAsync(login);
        if (userByLogin == null || userByLogin.Deleted)
            return LogErrorAndCreateResult($"Пользователь с указанным логином {login} не найден в системе");

        var contact = await _contactsService.GetContactByIdAsync(userByLogin.ContactId);
        if (contact == null)
            return LogErrorAndCreateResult($"Не найден контакт по идентификатору контакта {userByLogin.ContactId}");

        var email = contact.Attributes?
            .FirstOrDefault(attribute => attribute.FieldName == ContactsConstants.EmailFieldName)?.FieldValue;
        if (string.IsNullOrEmpty(email))
            return LogErrorAndCreateResult($"Поле email контакта с идентификатором {userByLogin.ContactId} не найдено или не заполнено");

        return new UserInfoResult
        {
            User = userByLogin,
            Email = email
        };
    }

    private UserInfoResult LogErrorAndCreateResult(string logError, string errorMessage = null)
    {
        _logger.LogError(logError);
        return new UserInfoResult
        {
            ErrorMessage = errorMessage ?? AccountOptions.UserWithLoginOrEmailNotFoundErrorMessage
        };
    }

    private bool IsEmail(string data) =>
        Regex.IsMatch(data, @"\A(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)\Z", RegexOptions.IgnoreCase);

    private bool IsBlocked(UserIdentity user) =>
        user.LockoutEnd != null && user.LockoutEnd > DateTimeOffset.UtcNow;
}
