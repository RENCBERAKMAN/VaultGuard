using System;

namespace VaultGuard.Application.DTOs.Users;

/// <summary>
/// Kullanıcı bilgilerini güncellemek için kullanılan Veri Transfer Nesnesi (DTO).
/// Senior Standart: 'record' yerine 'class' kullanımı, testlerdeki 'Property assignment' hatalarını önlemek için daha esnektir.
/// </summary>
public class UpdateUserDto
{
    /// <summary>
    /// Güncellenecek kullanıcının benzersiz kimliği.
    /// HATA ÇÖZÜMÜ: Kesinlikle Guid türünde olmalı, string-guid dönüşüm hatalarını önler.
    /// </summary>
    public Guid Id { get; set; }

    // ============================================================================
    // PROFİL BİLGİLERİ
    // ============================================================================

    /// <summary>
    /// Kullanıcının adı.
    /// </summary>
    public string FirstName { get; set; } = string.Empty;

    /// <summary>
    /// Kullanıcının soyadı.
    /// </summary>
    public string LastName { get; set; } = string.Empty;

    /// <summary>
    /// İsteğe bağlı telefon numarası. Format doğrulaması FluentValidation ile yapılır.
    /// </summary>
    public string? PhoneNumber { get; set; }

    // ============================================================================
    // HESAP & YETKİ BİLGİLERİ (Opsiyonel Güncelleme)
    // ============================================================================

    /// <summary>
    /// Yeni e-posta adresi. Null ise e-posta güncellenmez.
    /// </summary>
    public string? Email { get; set; }

    /// <summary>
    /// Yeni kullanıcı adı. Null ise kullanıcı adı güncellenmez.
    /// </summary>
    public string? Username { get; set; }

    /// <summary>
    /// Kullanıcının sistemdeki rolü (Admin, User vb.).
    /// Sadece yetkili kullanıcılar tarafından değiştirilmelidir.
    /// </summary>
    public string? Role { get; set; }
}