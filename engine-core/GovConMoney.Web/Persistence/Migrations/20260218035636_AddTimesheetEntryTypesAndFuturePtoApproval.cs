using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace GovConMoney.Web.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddTimesheetEntryTypesAndFuturePtoApproval : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "EntryType",
                table: "TimesheetLines",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.CreateTable(
                name: "FuturePtoApprovals",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    WorkDate = table.Column<DateOnly>(type: "date", nullable: false),
                    ApprovedByUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Reason = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    ApprovedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_FuturePtoApprovals", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_FuturePtoApprovals_TenantId",
                table: "FuturePtoApprovals",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_FuturePtoApprovals_TenantId_UserId_WorkDate",
                table: "FuturePtoApprovals",
                columns: new[] { "TenantId", "UserId", "WorkDate" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "FuturePtoApprovals");

            migrationBuilder.DropColumn(
                name: "EntryType",
                table: "TimesheetLines");
        }
    }
}
