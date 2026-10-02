import { Button, Center, Stack, Text, Title } from '@mantine/core'
import { Link } from 'react-router-dom'

export function NotFoundPage() {
  return (
    <Center mih="60vh">
      <Stack align="center" gap="sm">
        <Title order={2}>화면을 찾을 수 없습니다</Title>
        <Text c="dimmed">주소를 확인하거나 아래 버튼으로 돌아가십시오.</Text>
        <Button component={Link} to="/" mt="sm">
          개요로 이동
        </Button>
      </Stack>
    </Center>
  )
}
