use anchor_lang::prelude::*;
use anchor_spl::token_interface::{
    self, Mint, TokenAccount, TokenInterface, TransferChecked,
};
use groth16_solana::errors::Groth16Error;
use groth16_solana::groth16::Groth16Verifier;

declare_id!("APQauWUWYf1pd7BwG8xWe2eQT7uhXX4NRnRYQJfnAiYW");

pub const STATE_SEED: &[u8] = b"state";
pub const VAULT_SEED: &[u8] = b"vault";
pub const NULLIFIER_SEED: &[u8] = b"nullifier";
pub const MAX_DEPOSITS_PER_TX: usize = 20;

mod verifying_key;

#[program]
pub mod incognito_program {
    use super::*;

    pub fn initialize_pool(
        ctx: Context<Initialize>,
        denomination: u64,
        initial_root: [u8; 32],
        root_updater: Pubkey,
    ) -> Result<()> {
        let state = &mut ctx.accounts.state;
        state.mint = ctx.accounts.mint.key();
        state.denomination = denomination;
        state.root_updater = root_updater;
        state.merkle_root = initial_root;
        state.next_index = 0;
        state.state_bump = ctx.bumps.state;
        state.vault_bump = ctx.bumps.vault;

        Ok(())
    }

    pub fn set_root(ctx: Context<SetRoot>, new_root: [u8; 32]) -> Result<()> {
        require_keys_eq!(
            ctx.accounts.root_updater.key(),
            ctx.accounts.state.root_updater,
            IncognitoError::UnauthorizedRootUpdater
        );

        ctx.accounts.state.merkle_root = new_root;
        emit!(RootUpdatedEvent {
            state: ctx.accounts.state.key(),
            mint: ctx.accounts.state.mint,
            denomination: ctx.accounts.state.denomination,
            merkle_root: new_root,
            next_index: ctx.accounts.state.next_index,
        });
        Ok(())
    }

    pub fn deposit(ctx: Context<Deposit>, commitment: [u8; 32]) -> Result<()> {
        deposit_many_inner(ctx, vec![commitment])
    }

    pub fn deposit_many(ctx: Context<Deposit>, commitments: Vec<[u8; 32]>) -> Result<()> {
        deposit_many_inner(ctx, commitments)
    }

    pub fn action_withdraw(
        ctx: Context<ActionWithdraw>,
        proof: [u8; 256],
        nullifier_hash: [u8; 32],
    ) -> Result<()> {
        require_keys_eq!(
            ctx.accounts.mint.key(),
            ctx.accounts.state.mint,
            IncognitoError::InvalidMint
        );
        require_keys_eq!(
            ctx.accounts.destination.mint,
            ctx.accounts.state.mint,
            IncognitoError::InvalidMint
        );
        require_keys_eq!(
            ctx.accounts.vault.mint,
            ctx.accounts.state.mint,
            IncognitoError::InvalidMint
        );

        let proof_a: [u8; 64] = proof[0..64]
            .try_into()
            .map_err(|_| IncognitoError::InvalidProof)?;
        let proof_b: [u8; 128] = proof[64..192]
            .try_into()
            .map_err(|_| IncognitoError::InvalidProof)?;
        let proof_c: [u8; 64] = proof[192..256]
            .try_into()
            .map_err(|_| IncognitoError::InvalidProof)?;

        let public_inputs: [[u8; 32]; 2] = [ctx.accounts.state.merkle_root, nullifier_hash];
        let mut verifier = Groth16Verifier::<2>::new(
            &proof_a,
            &proof_b,
            &proof_c,
            &public_inputs,
            &verifying_key::VERIFYINGKEY,
        )
        .map_err(|e| {
            msg!("groth16 verifier init failed: {}", e);
            match e {
                Groth16Error::InvalidG1Length
                | Groth16Error::InvalidG2Length
                | Groth16Error::InvalidPublicInputsLength
                | Groth16Error::PublicInputGreaterThanFieldSize
                | Groth16Error::IncompatibleVerifyingKeyWithNrPublicInputs => {
                    IncognitoError::InvalidProof
                }
                _ => IncognitoError::Groth16SyscallFailed,
            }
        })?;

        verifier.verify().map_err(|e| {
            msg!("groth16 verify failed: {}", e);
            match e {
                Groth16Error::ProofVerificationFailed => IncognitoError::InvalidProof,
                _ => IncognitoError::Groth16SyscallFailed,
            }
        })?;

        let state_bump = ctx.accounts.state.state_bump;
        let denom_le = ctx.accounts.state.denomination.to_le_bytes();
        let signer_seeds: &[&[&[u8]]] = &[&[
            STATE_SEED,
            ctx.accounts.state.mint.as_ref(),
            denom_le.as_ref(),
            &[state_bump],
        ]];

        token_interface::transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.vault.to_account_info(),
                    mint: ctx.accounts.mint.to_account_info(),
                    to: ctx.accounts.destination.to_account_info(),
                    authority: ctx.accounts.state.to_account_info(),
                },
                signer_seeds,
            ),
            ctx.accounts.state.denomination,
            ctx.accounts.mint.decimals,
        )?;

        emit!(WithdrawEvent {
            state: ctx.accounts.state.key(),
            mint: ctx.accounts.state.mint,
            denomination: ctx.accounts.state.denomination,
            nullifier_hash,
            destination: ctx.accounts.destination.key(),
        });

        Ok(())
    }
}

fn deposit_many_inner(ctx: Context<Deposit>, commitments: Vec<[u8; 32]>) -> Result<()> {
    require_keys_eq!(
        ctx.accounts.mint.key(),
        ctx.accounts.state.mint,
        IncognitoError::InvalidMint
    );
    require_keys_eq!(
        ctx.accounts.depositor_token.mint,
        ctx.accounts.state.mint,
        IncognitoError::InvalidMint
    );
    require_keys_eq!(
        ctx.accounts.vault.mint,
        ctx.accounts.state.mint,
        IncognitoError::InvalidMint
    );

    require!(
        !commitments.is_empty() && commitments.len() <= MAX_DEPOSITS_PER_TX,
        IncognitoError::InvalidDepositCount
    );

    let amount = (ctx.accounts.state.denomination as u128)
        .checked_mul(commitments.len() as u128)
        .ok_or(IncognitoError::DepositAmountOverflow)? as u64;

    token_interface::transfer_checked(
        CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            TransferChecked {
                from: ctx.accounts.depositor_token.to_account_info(),
                mint: ctx.accounts.mint.to_account_info(),
                to: ctx.accounts.vault.to_account_info(),
                authority: ctx.accounts.depositor.to_account_info(),
            },
        ),
        amount,
        ctx.accounts.mint.decimals,
    )?;

    for commitment in commitments {
        let index = ctx.accounts.state.next_index;
        ctx.accounts.state.next_index = ctx
            .accounts
            .state
            .next_index
            .checked_add(1)
            .ok_or(IncognitoError::IndexOverflow)?;

        emit!(DepositEvent {
            state: ctx.accounts.state.key(),
            mint: ctx.accounts.state.mint,
            denomination: ctx.accounts.state.denomination,
            commitment,
            index,
        });
    }
    Ok(())
}

#[derive(Accounts)]
#[instruction(denomination: u64, initial_root: [u8; 32], root_updater: Pubkey)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(
        init,
        payer = payer,
        space = IncognitoState::SPACE,
        seeds = [STATE_SEED, mint.key().as_ref(), &denomination.to_le_bytes()],
        bump
    )]
    pub state: Account<'info, IncognitoState>,

    #[account(
        init,
        payer = payer,
        seeds = [VAULT_SEED, state.key().as_ref()],
        bump,
        token::mint = mint,
        token::authority = state,
        token::token_program = token_program
    )]
    pub vault: InterfaceAccount<'info, TokenAccount>,

    pub mint: InterfaceAccount<'info, Mint>,

    pub system_program: Program<'info, System>,
    pub token_program: Interface<'info, TokenInterface>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct SetRoot<'info> {
    pub root_updater: Signer<'info>,

    #[account(
        mut,
        seeds = [STATE_SEED, state.mint.as_ref(), &state.denomination.to_le_bytes()],
        bump = state.state_bump
    )]
    pub state: Account<'info, IncognitoState>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub depositor: Signer<'info>,

    #[account(mut, constraint = depositor_token.owner == depositor.key())]
    pub depositor_token: InterfaceAccount<'info, TokenAccount>,

    #[account(
        mut,
        seeds = [STATE_SEED, state.mint.as_ref(), &state.denomination.to_le_bytes()],
        bump = state.state_bump
    )]
    pub state: Account<'info, IncognitoState>,

    #[account(mut, seeds = [VAULT_SEED, state.key().as_ref()], bump = state.vault_bump)]
    pub vault: InterfaceAccount<'info, TokenAccount>,

    pub mint: InterfaceAccount<'info, Mint>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
#[instruction(proof: [u8; 256], nullifier_hash: [u8; 32])]
pub struct ActionWithdraw<'info> {
    #[account(mut)]
    pub relayer: Signer<'info>,

    #[account(
        mut,
        seeds = [STATE_SEED, state.mint.as_ref(), &state.denomination.to_le_bytes()],
        bump = state.state_bump
    )]
    pub state: Account<'info, IncognitoState>,

    #[account(mut, seeds = [VAULT_SEED, state.key().as_ref()], bump = state.vault_bump)]
    pub vault: InterfaceAccount<'info, TokenAccount>,

    #[account(
        init,
        payer = relayer,
        space = Nullifier::SPACE,
        seeds = [NULLIFIER_SEED, state.key().as_ref(), nullifier_hash.as_ref()],
        bump
    )]
    pub nullifier: Account<'info, Nullifier>,

    #[account(mut)]
    pub destination: InterfaceAccount<'info, TokenAccount>,

    pub mint: InterfaceAccount<'info, Mint>,

    pub system_program: Program<'info, System>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[account]
pub struct IncognitoState {
    pub mint: Pubkey,
    pub denomination: u64,
    pub root_updater: Pubkey,
    pub merkle_root: [u8; 32],
    pub next_index: u32,
    pub state_bump: u8,
    pub vault_bump: u8,
}

impl IncognitoState {
    pub const SPACE: usize = 8 + 32 + 8 + 32 + 32 + 4 + 1 + 1;
}

#[account]
pub struct Nullifier {}

impl Nullifier {
    pub const SPACE: usize = 8;
}

#[event]
pub struct DepositEvent {
    pub state: Pubkey,
    pub mint: Pubkey,
    pub denomination: u64,
    pub commitment: [u8; 32],
    pub index: u32,
}

#[event]
pub struct RootUpdatedEvent {
    pub state: Pubkey,
    pub mint: Pubkey,
    pub denomination: u64,
    pub merkle_root: [u8; 32],
    pub next_index: u32,
}

#[event]
pub struct WithdrawEvent {
    pub state: Pubkey,
    pub mint: Pubkey,
    pub denomination: u64,
    pub nullifier_hash: [u8; 32],
    pub destination: Pubkey,
}

#[error_code]
pub enum IncognitoError {
    #[msg("Caller is not the configured root updater.")]
    UnauthorizedRootUpdater,
    #[msg("Token mint does not match the configured mint.")]
    InvalidMint,
    #[msg("Invalid deposit count (must be 1..=20).")]
    InvalidDepositCount,
    #[msg("Deposit amount overflow.")]
    DepositAmountOverflow,
    #[msg("Deposit index overflow.")]
    IndexOverflow,
    #[msg("Invalid Groth16 proof.")]
    InvalidProof,
    #[msg("Groth16 verifier syscall failed (alt_bn128).")]
    Groth16SyscallFailed,
}

#[cfg(test)]
mod tests {
    // Intentionally empty: devnet-first MVP (no local validator/unit-test harness).
}
