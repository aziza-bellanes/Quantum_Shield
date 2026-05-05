import React from 'react'
import { Bar, BarChart, CartesianGrid, XAxis, YAxis, Cell } from 'recharts'
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from '../ui/chart'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../ui/card'
import type { TlsEntry } from '../../lib/types'

const DEFAULT_DATA: TlsEntry[] = [
  { version: '1.0', count: 0, color: '#ef4444' },
  { version: '1.1', count: 0, color: '#f97316' },
  { version: '1.2', count: 0, color: '#eab308' },
  { version: '1.3', count: 0, color: '#22c55e' },
]

interface Props {
  data?: TlsEntry[]
  title?: string
  description?: string
}

export const TlsBarChart: React.FC<Props> = ({ data, title, description }) => {
  const chartData = (data && data.length > 0 ? data : DEFAULT_DATA).map(d => ({
    version: `TLS ${d.version}`,
    count: d.count,
    fill: d.color,
  }))

  const chartConfig = Object.fromEntries(
    chartData.map(d => [d.version, { label: d.version, color: d.fill }])
  ) as ChartConfig

  return (
    <Card>
      <CardHeader>
        <CardTitle>{title ?? 'TLS Version Distribution'}</CardTitle>
        <CardDescription>{description ?? 'Analyzed applications by TLS protocol version'}</CardDescription>
      </CardHeader>
      <CardContent>

        <ChartContainer
          config={{ ...chartConfig, count: { label: 'Applications' } }}
          className="h-[220px] w-full [aspect-ratio:unset]"
        >
          <BarChart
            data={chartData}
            margin={{ top: 4, right: 4, bottom: 0, left: -16 }}
            barSize={40}
          >
            <CartesianGrid vertical={false} stroke="hsl(var(--border))" strokeOpacity={0.5} />
            <XAxis
              dataKey="version"
              tickLine={false}
              axisLine={false}
              tick={{ fontSize: 11 }}
            />
            <YAxis
              tickLine={false}
              axisLine={false}
              tick={{ fontSize: 11 }}
            />
            <ChartTooltip
              cursor={{ fill: 'hsl(var(--muted))', radius: 4 }}
              content={
                <ChartTooltipContent
                  nameKey="version"
                  hideLabel
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
            <Bar dataKey="count" radius={[5, 5, 0, 0]} fill="fill">
              {chartData.map((entry, i) => (
                <Cell key={i} fill={entry.fill} />
              ))}
            </Bar>
          </BarChart>
        </ChartContainer>

        <div className="mt-3 flex flex-wrap gap-3">
          {chartData.map(d => (
            <span
              key={d.version}
              className="flex items-center gap-1.5 font-mono text-[10px] text-muted-foreground"
            >
              <span
                className="inline-block h-2 w-2 rounded-[2px]"
                style={{ background: d.fill }}
              />
              {d.version}
            </span>
          ))}
        </div>
      </CardContent>
    </Card>
  )
}
