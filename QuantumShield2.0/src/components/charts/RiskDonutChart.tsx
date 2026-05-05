import React from 'react'
import { PieChart, Pie, Cell } from 'recharts'
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from '../ui/chart'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../ui/card'
import { Progress } from '../ui/progress'
import type { RiskEntry } from '../../lib/types'

const DEFAULT_DATA: RiskEntry[] = [
  { name: 'Low', value: 0, color: '#22c55e', fill: '#22c55e' },
  { name: 'Medium', value: 0, color: '#eab308', fill: '#eab308' },
  { name: 'High', value: 0, color: '#ef4444', fill: '#ef4444' },
]

interface Props {
  data?: RiskEntry[]
  title?: string
  description?: string
}

export const RiskDonutChart: React.FC<Props> = ({ data, title, description }) => {
  const chartData = data && data.length > 0 ? data : DEFAULT_DATA
  const total = chartData.reduce((s, d) => s + d.value, 0)

  const chartConfig: ChartConfig = {
    value: { label: 'Applications' },
    ...Object.fromEntries(chartData.map(d => [d.name, { label: `${d.name} Risk`, color: d.fill }])),
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>{title ?? 'Risk Distribution'}</CardTitle>
        <CardDescription>{description ?? 'Security risk levels across analyzed apps'}</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="flex items-center gap-5">
          <ChartContainer
            config={chartConfig}
            className="h-[160px] min-w-[160px] max-w-[160px] [aspect-ratio:unset] shrink-0"
          >
            <PieChart>
              <ChartTooltip
                cursor={false}
                content={
                  <ChartTooltipContent
                    hideLabel
                    nameKey="name"
                    formatter={(value, name) => (
                      <div className="flex w-full items-center justify-between gap-4">
                        <span className="text-muted-foreground">{name}</span>
                        <span className="font-mono font-semibold tabular-nums text-foreground">
                          {(value as number).toLocaleString()} apps
                        </span>
                      </div>
                    )}
                  />
                }
              />
              <Pie
                data={chartData}
                dataKey="value"
                nameKey="name"
                cx="50%"
                cy="50%"
                innerRadius={48}
                outerRadius={70}
                strokeWidth={0}
              >
                {chartData.map((entry, i) => (
                  <Cell key={i} fill={entry.fill} />
                ))}
              </Pie>
            </PieChart>
          </ChartContainer>

          <div className="flex flex-1 flex-col gap-3">
            {chartData.map(d => (
              <div key={d.name}>
                <div className="mb-1.5 flex items-center justify-between">
                  <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
                    <span className="inline-block h-2 w-2 rounded-[2px]" style={{ background: d.fill }} />
                    {d.name} Risk
                  </span>
                  <span className="font-mono text-xs font-semibold text-foreground">{d.value}</span>
                </div>
                <Progress
                  value={total > 0 ? Math.round((d.value / total) * 100) : 0}
                  indicatorClassName={
                    d.name === 'Low' ? 'bg-emerald-500' : d.name === 'Medium' ? 'bg-yellow-500' : 'bg-red-500'
                  }
                />
              </div>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
