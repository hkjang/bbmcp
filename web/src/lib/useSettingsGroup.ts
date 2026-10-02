import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { notifications } from '@mantine/notifications'
import { useEffect, useState } from 'react'
import { api, type SettingsEnvelope } from './api'

/**
 * useSettingsGroup loads one admin settings group, keeps a local draft, and
 * saves it back. Secret fields travel in a separate map so an empty box never
 * overwrites a stored credential.
 */
export function useSettingsGroup<T extends object>(group: string) {
  const queryClient = useQueryClient()
  const query = useQuery({
    queryKey: ['settings', group],
    queryFn: () => api.get<SettingsEnvelope<T>>(`/api/admin/settings/${group}`),
  })

  const [draft, setDraft] = useState<T | null>(null)
  const [secrets, setSecrets] = useState<Record<string, string>>({})

  useEffect(() => {
    if (query.data) {
      setDraft(query.data.value)
      setSecrets({})
    }
  }, [query.data])

  const save = useMutation({
    mutationFn: async () => {
      const payload = {
        value: draft,
        secrets: Object.fromEntries(
          Object.entries(secrets).filter(([, v]) => v.trim() !== ''),
        ),
      }
      return api.put<SettingsEnvelope<T>>(`/api/admin/settings/${group}`, payload)
    },
    onSuccess: (data) => {
      queryClient.setQueryData(['settings', group], data)
      setDraft(data.value)
      setSecrets({})
      void queryClient.invalidateQueries({ queryKey: ['dashboard'] })
      void queryClient.invalidateQueries({ queryKey: ['me'] })
      notifications.show({ color: 'teal', title: '저장했습니다', message: '설정이 적용되었습니다.' })
    },
    onError: (err: unknown) => {
      notifications.show({
        color: 'red',
        title: '저장 실패',
        message: err instanceof Error ? err.message : '설정을 저장할 수 없습니다.',
      })
    },
  })

  return {
    query,
    draft,
    setDraft,
    secrets,
    setSecrets,
    secretPresence: query.data?.secrets ?? {},
    limits: query.data?.limits ?? {},
    save,
  }
}

/** useConnectivityTest runs one of the admin /test/{target} probes. */
export function useConnectivityTest(target: string) {
  return useMutation({
    mutationFn: (queryString?: string) =>
      api.post<Record<string, unknown>>(`/api/admin/test/${target}${queryString ?? ''}`),
  })
}
