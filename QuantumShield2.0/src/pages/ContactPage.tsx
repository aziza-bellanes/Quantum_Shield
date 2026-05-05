import React, { useState } from 'react'
import { z } from 'zod'
import { User, Mail, MessageSquare, Send, Phone, MapPin, Clock } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Separator } from '../components/ui/separator'
import { Badge } from '../components/ui/badge'
import { contactApi, ApiError } from '../lib/api'

const contactSchema = z.object({
  name: z
    .string()
    .min(1, 'Name is required')
    .min(2, 'Name must be at least 2 characters'),
  email: z
    .string()
    .min(1, 'Email is required')
    .email('Please enter a valid email address'),
  subject: z
    .string()
    .min(1, 'Subject is required')
    .min(5, 'Subject must be at least 5 characters')
    .max(100, 'Subject must be under 100 characters'),
  message: z
    .string()
    .min(1, 'Message is required')
    .min(20, 'Message must be at least 20 characters')
    .max(2000, 'Message must be under 2000 characters'),
})

type ContactForm = z.infer<typeof contactSchema>
type FormErrors = Partial<Record<keyof ContactForm, string>>

const FieldError: React.FC<{ msg?: string }> = ({ msg }) =>
  msg ? <p className="mt-1 text-[11px] text-destructive">{msg}</p> : null

interface ContactInfoItem {
  icon: React.ReactNode
  label: string
  value: string
  href?: string
  sub: string
}

const contactInfo: ContactInfoItem[] = [
  {
    icon: <Mail size={16} />,
    label: 'Email',
    value: 'Quantum.Shield.Support@gmail.com',
    href: 'mailto:Quantum.Shield.Support@gmail.com',
    sub: 'We reply within 24 hours',
  },
  {
    icon: <Phone size={16} />,
    label: 'Phone',
    value: '+216 41 654 492',
    href: 'tel:+21641654492',
    sub: 'Mon–Fri, 9am–6pm EST',
  },
  {
    icon: <MapPin size={16} />,
    label: 'Headquarters',
    value: 'Manouba, Tunisia',
    sub: 'ENSI, Manouba University Campus',
  },
  {
    icon: <Clock size={16} />,
    label: 'Response SLA',
    value: '< 4 hours',
    sub: 'For critical security issues',
  },
]

const InfoPanel: React.FC = () => (
  <div className="flex flex-col gap-4 lg:sticky lg:top-6 lg:self-start">
    <Card>
      <CardHeader>
        <CardTitle>Contact Info</CardTitle>
        <CardDescription>Multiple ways to reach us</CardDescription>
      </CardHeader>
      <Separator />
      <CardContent className="pt-4">
        <div className="flex flex-col gap-4">
          {contactInfo.map((info, i) => (
            <React.Fragment key={info.label}>
              {i > 0 && <Separator />}
              <div className="flex items-start gap-3">
                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-muted text-muted-foreground">
                  {info.icon}
                </div>
                <div className="min-w-0">
                  <p className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">{info.label}</p>
                  {info.href ? (
                    <a
                      href={info.href}
                      className="mt-0.5 block break-all text-sm font-medium text-foreground hover:text-primary transition-colors"
                    >
                      {info.value}
                    </a>
                  ) : (
                    <p className="mt-0.5 break-all text-sm font-medium text-foreground">{info.value}</p>
                  )}
                  <p className="text-[11px] text-muted-foreground">{info.sub}</p>
                </div>
              </div>
            </React.Fragment>
          ))}
        </div>
      </CardContent>
    </Card>
    <Card>
      <CardContent className="pt-5">
        <div className="flex flex-col gap-3">
          <div className="flex items-center justify-between">
            <p className="text-sm font-semibold text-foreground">System Status</p>
            <Badge variant="success">All systems go</Badge>
          </div>
          <Separator />
          {[
            { name: 'API', status: 'Operational' },
            { name: 'Dashboard', status: 'Operational' },
            { name: 'PQC Analyzer', status: 'Operational' },
            { name: 'Notifications', status: 'Operational' },
          ].map(s => (
            <div key={s.name} className="flex items-center justify-between">
              <span className="text-xs text-muted-foreground">{s.name}</span>
              <span className="flex items-center gap-1.5 font-mono text-[10px] text-emerald-500">
                <span className="inline-block h-1.5 w-1.5 rounded-full bg-emerald-500" />
                {s.status}
              </span>
            </div>
          ))}
          <Separator />
          <p className="font-mono text-[10px] text-muted-foreground">Last checked: just now</p>
        </div>
      </CardContent>
    </Card>
  </div>
)

export const ContactPage: React.FC = () => {
  const [form, setForm] = useState<ContactForm>({ name: '', email: '', subject: '', message: '' })
  const [errors, setErrors] = useState<FormErrors>({})
  const [touched, setTouched] = useState<Partial<Record<keyof ContactForm, boolean>>>({})
  const [sent, setSent] = useState(false)
  const [loading, setLoading] = useState(false)
  const [serverError, setServerError] = useState('')

  const validate = (d: ContactForm): FormErrors => {
    const r = contactSchema.safeParse(d)
    if (r.success) return {}
    return r.error.issues.reduce<FormErrors>((a, i) => {
      const k = i.path[0] as keyof ContactForm; if (!a[k]) a[k] = i.message; return a
    }, {})
  }

  const handleChange = (f: keyof ContactForm) => (
    e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>,
  ) => {
    const next = { ...form, [f]: e.target.value }; setForm(next)
    if (touched[f]) setErrors(validate(next))
  }

  const handleBlur = (f: keyof ContactForm) => () => {
    setTouched(t => ({ ...t, [f]: true })); setErrors(validate(form))
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    const allT: Record<keyof ContactForm, boolean> = { name: true, email: true, subject: true, message: true }
    setTouched(allT); const errs = validate(form); setErrors(errs)
    if (Object.keys(errs).length > 0) return

    setLoading(true)
    setServerError('')
    try {
      await contactApi.send(form.name, form.email, form.subject, form.message)
      setSent(true)
    } catch (err) {
      setServerError(err instanceof ApiError ? err.message : 'Failed to send message. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  if (sent) {
    return (
      <div className="grid h-full grid-cols-1 gap-5 p-6 lg:grid-cols-[1fr_300px]">
        <Card className="flex items-center justify-center">
          <CardContent className="flex flex-col items-center gap-4 py-20 text-center">
            <div className="flex h-14 w-14 items-center justify-center rounded-full bg-emerald-500/10">
              <Send size={24} className="text-emerald-500" />
            </div>
            <div>
              <h2 className="text-base font-semibold text-foreground">Message sent!</h2>
              <p className="mt-1 text-sm text-muted-foreground">
                We'll get back to you within 24 hours.
              </p>
            </div>
            <Button variant="outline" size="sm" onClick={() => {
              setSent(false)
              setForm({ name: '', email: '', subject: '', message: '' })
              setTouched({})
            }}>
              Send another message
            </Button>
          </CardContent>
        </Card>
        <InfoPanel />
      </div>
    )
  }

  return (
    <div className="grid h-full grid-cols-1 gap-5 p-6 lg:grid-cols-[1fr_300px]">

      <Card className="flex flex-col">
        <CardHeader>
          <div className="flex items-center gap-2.5">
            <span className="text-muted-foreground"><MessageSquare size={16} /></span>
            <div>
              <CardTitle>Send us a message</CardTitle>
              <CardDescription>Fill in the form and we'll get back to you shortly</CardDescription>
            </div>
            <Badge variant="success" className="ml-auto">Online</Badge>
          </div>
        </CardHeader>
        <Separator />
        <CardContent className="flex-1 pt-5">
          <form onSubmit={handleSubmit} noValidate className="flex h-full flex-col gap-4">
            {serverError && <p className="text-[11px] text-destructive">{serverError}</p>}
            <div className="grid gap-4 sm:grid-cols-2">
              <div>
                <label className="mb-1.5 block font-mono text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Full Name</label>
                <Input placeholder="Lay Mertilly" value={form.name} onChange={handleChange('name')} onBlur={handleBlur('name')} icon={<User size={13} />} className={errors.name && touched.name ? 'border-destructive' : ''} />
                <FieldError msg={touched.name ? errors.name : undefined} />
              </div>
              <div>
                <label className="mb-1.5 block font-mono text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Email Address</label>
                <Input type="email" placeholder="you@company.com" value={form.email} onChange={handleChange('email')} onBlur={handleBlur('email')} icon={<Mail size={13} />} className={errors.email && touched.email ? 'border-destructive' : ''} />
                <FieldError msg={touched.email ? errors.email : undefined} />
              </div>
            </div>

            <div>
              <label className="mb-1.5 block font-mono text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Subject</label>
              <Input placeholder="e.g. Question about PQC scoring" value={form.subject} onChange={handleChange('subject')} onBlur={handleBlur('subject')} className={errors.subject && touched.subject ? 'border-destructive' : ''} />
              <FieldError msg={touched.subject ? errors.subject : undefined} />
            </div>

            <div className="flex flex-1 flex-col">
              <div className="mb-1.5 flex items-center justify-between">
                <label className="font-mono text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Message</label>
                <span className="font-mono text-[10px] text-muted-foreground">{form.message.length}/2000</span>
              </div>
              <textarea
                placeholder="Describe your question or issue in detail…"
                value={form.message}
                onChange={handleChange('message')}
                onBlur={handleBlur('message')}
                rows={8}
                className={[
                  'flex w-full flex-1 resize-none rounded-md border bg-background px-3 py-2',
                  'text-sm text-foreground placeholder:text-muted-foreground',
                  'shadow-sm transition-colors focus:outline-none focus:ring-2 focus:ring-ring',
                  errors.message && touched.message ? 'border-destructive' : 'border-input',
                ].join(' ')}
              />
              <FieldError msg={touched.message ? errors.message : undefined} />
            </div>

            <div className="flex items-center justify-between border-t border-border pt-4">
              <p className="text-[11px] text-muted-foreground">
                Average response time: <span className="font-semibold text-foreground">~2 hours</span>
              </p>
              <Button type="submit" className="gap-2" disabled={loading} aria-busy={loading}>
                {loading
                  ? <><span aria-hidden="true" className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-current border-t-transparent inline-block" /> Sending…</>
                  : <><Send size={13} /> Send Message</>}
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>

      <InfoPanel />
    </div>
  )
}
