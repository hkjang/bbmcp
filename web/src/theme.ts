import { createTheme, type MantineThemeOverride } from '@mantine/core'

// bbmcp uses a deliberately larger type scale than Mantine's default: this is
// an operations console read on projector screens and shared monitors, so the
// smallest body text is 14px rather than 12px.
export const theme: MantineThemeOverride = createTheme({
  primaryColor: 'bbblue',
  primaryShade: { light: 6, dark: 5 },
  defaultRadius: 'md',
  fontFamily:
    "'Pretendard Variable', Pretendard, -apple-system, BlinkMacSystemFont, 'Malgun Gothic', 'Apple SD Gothic Neo', 'Noto Sans KR', system-ui, sans-serif",
  fontFamilyMonospace:
    "'JetBrains Mono', 'D2Coding', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
  headings: {
    fontWeight: '700',
    sizes: {
      h1: { fontSize: '2rem', lineHeight: '1.3' },
      h2: { fontSize: '1.625rem', lineHeight: '1.35' },
      h3: { fontSize: '1.375rem', lineHeight: '1.4' },
      h4: { fontSize: '1.175rem', lineHeight: '1.45' },
      h5: { fontSize: '1.05rem', lineHeight: '1.5' },
    },
  },
  fontSizes: {
    xs: '0.8125rem',
    sm: '0.9375rem',
    md: '1rem',
    lg: '1.125rem',
    xl: '1.3125rem',
  },
  lineHeights: { xs: '1.5', sm: '1.55', md: '1.6', lg: '1.65', xl: '1.7' },
  colors: {
    bbblue: [
      '#e7f1ff', '#cfe0ff', '#9dc0ff', '#689dff', '#3f80fe',
      '#246efe', '#1f6feb', '#135bd1', '#0b4fbb', '#0043a6',
    ],
  },
  components: {
    Button: { defaultProps: { size: 'md' } },
    TextInput: { defaultProps: { size: 'md' } },
    PasswordInput: { defaultProps: { size: 'md' } },
    NumberInput: { defaultProps: { size: 'md' } },
    Textarea: { defaultProps: { size: 'md' } },
    Select: { defaultProps: { size: 'md', allowDeselect: false, checkIconPosition: 'right' } },
    MultiSelect: { defaultProps: { size: 'md' } },
    Switch: { defaultProps: { size: 'md' } },
    Table: { defaultProps: { fz: 'sm', verticalSpacing: 'sm', horizontalSpacing: 'md' } },
    Badge: { defaultProps: { size: 'md', tt: 'none' } },
    Tooltip: { defaultProps: { withArrow: true, fz: 'sm' } },
    Modal: { defaultProps: { centered: true, overlayProps: { blur: 2 } } },
  },
})
