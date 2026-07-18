package account

import (
	"testing"
	"time"
)

func TestBillingPlanSignalsIgnoreUsagePercentAlone(t *testing.T) {
	if (Billing{CreditUsagePercent: 42.5}).IsPaid() {
		t.Fatal("usage percent alone must not classify billing as paid")
	}
	if !(Billing{PlanName: "SuperGrok", UsagePeriodType: "USAGE_PERIOD_TYPE_WEEKLY"}).IsPaid() {
		t.Fatal("SuperGrok plan should classify as paid even at zero usage")
	}
	if !(Billing{PlanCode: "free-tier"}).HasFreeProfileSignal() {
		t.Fatal("free-tier plan should classify as a free profile")
	}
	if (Billing{CreditUsagePercent: 42.5, IsUnifiedBillingUser: true, UsagePeriodType: "USAGE_PERIOD_TYPE_WEEKLY"}).HasFreeProfileSignal() {
		t.Fatal("generic billing fields must not classify a profile as free")
	}
}

func TestBillingIsExhaustedForOnDemandCredits(t *testing.T) {
	if !(Billing{OnDemandCap: 50, CreditUsagePercent: 100}).IsExhausted(0) {
		t.Fatal("expected exhausted on-demand billing")
	}
	if (Billing{CreditUsagePercent: 100}).IsExhausted(0) {
		t.Fatal("billing without a reported limit should not be treated as exhausted")
	}
	if !(Billing{CreditUsagePercent: 100, UsagePeriodType: "USAGE_PERIOD_TYPE_WEEKLY"}).IsExhausted(0) {
		t.Fatal("expected exhausted weekly usage period")
	}
}

func TestBillingPeriodEndMatchesExhaustedLimit(t *testing.T) {
	monthlyEnd := "2026-08-01T00:00:00Z"
	weeklyEnd := "2026-07-19T00:00:00Z"
	weekly := Billing{MonthlyLimit: 15_000, Used: 197, CreditUsagePercent: 100, UsagePeriodType: "USAGE_PERIOD_TYPE_WEEKLY", UsagePeriodEnd: weeklyEnd, BillingPeriodEnd: monthlyEnd}
	if value, ok := weekly.PeriodEnd(); !ok || value.Format(time.RFC3339) != weeklyEnd {
		t.Fatalf("weekly period end = %v, %v", value, ok)
	}
	monthly := Billing{MonthlyLimit: 15_000, Used: 15_000, CreditUsagePercent: 5, UsagePeriodType: "USAGE_PERIOD_TYPE_WEEKLY", UsagePeriodEnd: weeklyEnd, BillingPeriodEnd: monthlyEnd}
	if value, ok := monthly.PeriodEnd(); !ok || value.Format(time.RFC3339) != monthlyEnd {
		t.Fatalf("monthly period end = %v, %v", value, ok)
	}
}
