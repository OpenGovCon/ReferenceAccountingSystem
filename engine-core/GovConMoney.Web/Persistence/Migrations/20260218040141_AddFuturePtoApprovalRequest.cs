using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace GovConMoney.Web.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddFuturePtoApprovalRequest : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "FuturePtoApprovalRequests",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    WorkDate = table.Column<DateOnly>(type: "date", nullable: false),
                    RequestedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Reason = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    RequestedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_FuturePtoApprovalRequests", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_FuturePtoApprovalRequests_TenantId",
                table: "FuturePtoApprovalRequests",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_FuturePtoApprovalRequests_TenantId_UserId_WorkDate",
                table: "FuturePtoApprovalRequests",
                columns: new[] { "TenantId", "UserId", "WorkDate" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "FuturePtoApprovalRequests");
        }
    }
}
