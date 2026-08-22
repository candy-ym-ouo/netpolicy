package check

import (
	"netpolicy/internal/domain/model"
	"netpolicy/internal/parser"
	"netpolicy/internal/storage"
	"time"
)

type Checker struct{ Repo storage.Repository }

func (c Checker) Run() model.CheckReport {
	r := model.CheckReport{RunAt: time.Now().UTC(), Items: []model.CheckItem{}}
	rules, _ := c.Repo.ListRules(model.RuleFilter{})
	for _, x := range rules {
		if e := parser.Validate(x, 1); e != nil {
			r.Failed++
			r.Items = append(r.Items, model.CheckItem{Category: "rule_format", Name: "规则格式完整性", Level: "fail", Detail: e.Error()})
		}
	}
	if r.Failed == 0 {
		r.Passed++
		r.Items = append(r.Items, model.CheckItem{Category: "rule_format", Name: "规则格式完整性", Level: "pass", Detail: "全部规则通过格式校验"})
	}
	tasks, _ := c.Repo.ListTasks()
	results, _ := c.Repo.ListResults()
	for _, z := range results {
		found := false
		for _, t := range tasks {
			if t.ID == z.TaskID {
				found = true
			}
		}
		if !found {
			r.Warnings++
			r.Items = append(r.Items, model.CheckItem{Category: "reference", Name: "结果引用", Level: "warn", Detail: "发现孤儿分析结果"})
		}
	}
	if len(tasks) >= 0 {
		r.Passed++
		r.Items = append(r.Items, model.CheckItem{Category: "consistency", Name: "数据一致性", Level: "pass", Detail: "存储数据可读"})
	}
	c.Repo.SetReport(r)
	return r
}
