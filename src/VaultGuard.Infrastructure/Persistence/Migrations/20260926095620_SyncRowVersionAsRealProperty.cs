using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace VaultGuard.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class SyncRowVersionAsRealProperty : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<byte[]>(
                name: "RowVersion",
                table: "Secrets",
                type: "rowversion",
                rowVersion: true,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "RowVersion",
                table: "Secrets");
        }
    }
}
