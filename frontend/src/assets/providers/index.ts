import githubCopilot from '@lobehub/icons-static-svg/icons/githubcopilot.svg';
import openAI from '@lobehub/icons-static-svg/icons/openai.svg';
import microsoft from '@lobehub/icons-static-svg/icons/microsoft-color.svg';
import claude from '@lobehub/icons-static-svg/icons/claude-color.svg';
import ollama from '@lobehub/icons-static-svg/icons/ollama.svg';

export const providerIcons = {
    github: githubCopilot,
    openai: openAI,
    azure: microsoft,
    anthropic: claude,
    local: ollama,
} as const;