using Nbt.Identity.Contract.Entities;
using Nbt.Identity.Domain.Dto;
using Nbt.ManageUser.Contract.Dto;

namespace Nbt.Identity.Application.Services.RestorePassword;

/// <summary>
/// Интерфейс сервиса восстановления пароля
/// </summary>
public interface IRestorePasswordService
{
    /// <summary>
    /// Генерация ссылки восстановления пароля
    /// </summary>
    /// <param name="userId">Идентификатор пользователя</param>
    /// <param name="returnUrl">Url-адрес для возврата после успешной авторизации</param>
    /// <param name="restoreEndpoint">Ендпоинт восстановления пароля</param>
    /// <returns>Ссылка восстановления пароля</returns>
    Task<string> GenerateRestorePasswordLinkAsync(long userId, string returnUrl, string restoreEndpoint = null);

    /// <summary>
    /// Валидация токена восстановления пароля
    /// </summary>
    /// <param name="userId">Идентификатор пользователя</param>
    /// <param name="token">Токен восстановления</param>
    /// <returns>Результат валидации токена восстановления пароля</returns>
    Task<ValidateRestorePasswordTokenResult> ValidateRestorePasswordTokenAsync(long userId, string token);

    /// <summary>
    /// Восстановление пароля
    /// </summary>
    /// <param name="loginOrEmail">Логин или e-mail пользователя</param>
    /// <param name="returnUrl">Url-адрес для возврата после успешной авторизации</param>
    /// <param name="restoreEndpoint">Ендпоинт восстановления пароля</param>
    /// <returns>Текст возникшей ошибки, null - при отсутствии</returns>
    Task<string> RestorePasswordAsync(string loginOrEmail, string returnUrl, string restoreEndpoint = null);

    /// <summary>
    /// Восстановление пароля пользователя Супервизора
    /// </summary>
    /// <param name="supervisorUser">Сущность пользователя Супервизора</param>
    /// <returns><inheritdoc cref="UserInfoResult"/></returns>
    Task<UserInfoResult> RestoreSupervisorPasswordAsync(UserIdentity supervisorUser);

    /// <summary>
    /// Генерирует случайный пароль в соответствии с требованиями
    /// </summary>
    /// <returns><inheritdoc cref="PasswordDto"/></returns>
    public PasswordDto GeneratePassword();
}
