package storage

import (
	"errors"
	"netpolicy/internal/domain/model"
)

var ErrNotFound = errors.New("not found")
var ErrConflict = errors.New("conflict")

type Repository interface {
	SaveRules([]model.Rule) error
	ReplaceAllRules([]model.Rule) error
	ListRules(model.RuleFilter) ([]model.Rule, error)
	GetRule(string) (model.Rule, bool)
	DeleteRule(string) error
	RulesetVersion() int
	CreateTask(*model.AnalysisTask) error
	UpdateTask(*model.AnalysisTask) error
	GetTask(string) (model.AnalysisTask, bool)
	ListTasks() ([]model.AnalysisTask, error)
	CASStatus(string, string, string) (bool, error)
	SaveResult(*model.AnalysisResult) error
	GetResult(string) (model.AnalysisResult, bool)
	ListResults() ([]model.AnalysisResult, error)
	AppendAuditLog(model.AuditLog) error
	ListAuditLogs(int) ([]model.AuditLog, error)
	SetReport(model.CheckReport)
	LatestReport() (model.CheckReport, bool)
	Export() ([]byte, error)
	Import([]byte) error
	Close() error
}
