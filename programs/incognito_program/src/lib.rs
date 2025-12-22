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
pub const NULLIFIER_PAGE_SEED: &[u8] = b"nullifier_page";
pub const V2_SEED: &[u8] = b"v2";
pub const MAX_DEPOSITS_PER_TX: usize = 20;
pub const ROOT_HISTORY_SIZE: usize = 32;
// Keep this small enough to avoid Solana BPF stack issues with Anchor account deserialization.
pub const NULLIFIER_PAGE_CAPACITY: usize = 96;

mod verifying_key;
mod verifying_key_v2;

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

    // -------------------------
    // v2: variable-amount notes + change commitments
    // -------------------------

    pub fn initialize_pool_v2(
        ctx: Context<InitializeV2>,
        initial_root: [u8; 32],
        root_updater: Pubkey,
    ) -> Result<()> {
        let state = &mut ctx.accounts.state;
        state.mint = ctx.accounts.mint.key();
        state.root_updater = root_updater;
        state.merkle_root = initial_root;
        state.next_index = 0;
        // Accounts are zero-initialized by `init`; avoid large stack assignments here.
        state.root_history[0] = initial_root;
        state.root_history_cursor = 1;
        state.state_bump = ctx.bumps.state;
        state.vault_bump = ctx.bumps.vault;
        Ok(())
    }

    pub fn set_root_v2(ctx: Context<SetRootV2>, new_root: [u8; 32]) -> Result<()> {
        require_keys_eq!(
            ctx.accounts.root_updater.key(),
            ctx.accounts.state.root_updater,
            IncognitoError::UnauthorizedRootUpdater
        );

        ctx.accounts.state.merkle_root = new_root;
        let i = ctx.accounts.state.root_history_cursor as usize % ROOT_HISTORY_SIZE;
        ctx.accounts.state.root_history[i] = new_root;
        ctx.accounts.state.root_history_cursor = ctx.accounts.state.root_history_cursor.wrapping_add(1);

        emit!(RootUpdatedEventV2 {
            state: ctx.accounts.state.key(),
            mint: ctx.accounts.state.mint,
            merkle_root: new_root,
            next_index: ctx.accounts.state.next_index,
        });
        Ok(())
    }

    pub fn deposit_v2(
        ctx: Context<DepositV2>,
        commitment: [u8; 32],
        amount: u64,
    ) -> Result<()> {
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
        require!(amount > 0, IncognitoError::InvalidDepositAmount);

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

        let index = ctx.accounts.state.next_index;
        ctx.accounts.state.next_index = ctx
            .accounts
            .state
            .next_index
            .checked_add(1)
            .ok_or(IncognitoError::IndexOverflow)?;

        emit!(DepositEventV2 {
            state: ctx.accounts.state.key(),
            mint: ctx.accounts.state.mint,
            commitment,
            index,
            is_change: false,
        });

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn withdraw_v2(
        ctx: Context<WithdrawV2>,
        proof: [u8; 256],
        root: [u8; 32],
        nullifier_hash: [u8; 32],
        withdraw_amount: u64,
        fee: u64,
        change_commitment: [u8; 32],
        nullifier_shard_byte: u8,
        nullifier_page_index: u16,
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
        require_keys_eq!(
            ctx.accounts.relayer_fee_ata.mint,
            ctx.accounts.state.mint,
            IncognitoError::InvalidMint
        );

        require!(
            nullifier_shard_byte == nullifier_hash[0],
            IncognitoError::InvalidNullifierShard
        );

        require!(is_known_root(&ctx.accounts.state, &root), IncognitoError::UnknownRoot);

        // Groth16 proof split
        let proof_a: [u8; 64] = proof[0..64]
            .try_into()
            .map_err(|_| IncognitoError::InvalidProof)?;
        let proof_b: [u8; 128] = proof[64..192]
            .try_into()
            .map_err(|_| IncognitoError::InvalidProof)?;
        let proof_c: [u8; 64] = proof[192..256]
            .try_into()
            .map_err(|_| IncognitoError::InvalidProof)?;

        let (recipient_lo, recipient_hi) = pubkey_to_u128_halves_le(&ctx.accounts.destination.owner);
        let (mint_lo, mint_hi) = pubkey_to_u128_halves_le(&ctx.accounts.state.mint);

        let public_inputs: [[u8; 32]; 9] = [
            root,
            nullifier_hash,
            u64_to_be_bytes32(withdraw_amount),
            u64_to_be_bytes32(fee),
            u128_to_be_bytes32(recipient_lo),
            u128_to_be_bytes32(recipient_hi),
            u128_to_be_bytes32(mint_lo),
            u128_to_be_bytes32(mint_hi),
            change_commitment,
        ];

        let mut verifier = Groth16Verifier::<9>::new(
            &proof_a,
            &proof_b,
            &proof_c,
            &public_inputs,
            &verifying_key_v2::VERIFYINGKEY,
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

        // Init/validate nullifier shard and page
        init_or_validate_nullifier_shard(
            ctx.accounts.nullifier_shard.as_mut(),
            ctx.accounts.state.key(),
            nullifier_shard_byte,
            ctx.bumps.nullifier_shard,
        )?;
        let existing_pages = ctx.accounts.nullifier_shard.page_count;

        // Scan for double-spend across all existing pages.
        let mut last_page_len: Option<u16> = None;
        for idx in 0..existing_pages {
            // If the insertion page is part of the existing set, scan it directly (avoid AccountInfo lifetime issues).
            if idx == nullifier_page_index {
                let page = ctx.accounts.nullifier_page.load()?;
                page.validate(ctx.accounts.state.key(), nullifier_shard_byte, idx)?;

                if page.contains(&nullifier_hash) {
                    return err!(IncognitoError::NullifierAlreadySpent);
                }

                if idx + 1 == existing_pages {
                    last_page_len = Some(page.len);
                }
                continue;
            }

            let expected = expected_nullifier_page_pda(
                ctx.program_id,
                ctx.accounts.state.key(),
                nullifier_shard_byte,
                idx,
            );
            let ai = ctx
                .remaining_accounts
                .iter()
                .find(|a| a.key() == expected)
                .ok_or_else(|| error!(IncognitoError::MissingNullifierPage))?;
            let (page_len, contains) = nullifier_page_contains_and_len(
                ai,
                ctx.accounts.state.key(),
                nullifier_shard_byte,
                idx,
                &nullifier_hash,
            )?;

            if contains {
                return err!(IncognitoError::NullifierAlreadySpent);
            }

            if idx + 1 == existing_pages {
                last_page_len = Some(page_len);
            }
        }

        // Determine insertion page rules (append-only pages)
        if existing_pages == 0 {
            require!(nullifier_page_index == 0, IncognitoError::InvalidNullifierPage);
        } else if nullifier_page_index < existing_pages {
            // Must write to the current last page.
            require!(
                nullifier_page_index + 1 == existing_pages,
                IncognitoError::InvalidNullifierPage
            );
        } else if nullifier_page_index == existing_pages {
            // Creating a new page requires the previous last page to be full.
            require!(
                last_page_len.unwrap_or(0) as usize >= NULLIFIER_PAGE_CAPACITY,
                IncognitoError::InvalidNullifierPage
            );
        } else {
            return err!(IncognitoError::InvalidNullifierPage);
        }

        // Init/validate the insertion page, then append.
        {
            let mut page = ctx.accounts.nullifier_page.load_mut()?;
            init_or_validate_nullifier_page(
                &mut page,
                ctx.accounts.state.key(),
                nullifier_shard_byte,
                nullifier_page_index,
                ctx.bumps.nullifier_page,
            )?;

            if page.len as usize >= NULLIFIER_PAGE_CAPACITY {
                return err!(IncognitoError::NullifierPageFull);
            }

            // If this is a newly created page, bump shard.page_count.
            if nullifier_page_index + 1 > ctx.accounts.nullifier_shard.page_count {
                ctx.accounts.nullifier_shard.page_count = nullifier_page_index + 1;
            }

            let insert_i = page.len as usize;
            page.hashes[insert_i] = nullifier_hash;
            page.len = page
                .len
                .checked_add(1)
                .ok_or(IncognitoError::IndexOverflow)?;
        }

        // Transfer funds
        let state_bump = ctx.accounts.state.state_bump;
        let signer_seeds: &[&[&[u8]]] = &[&[
            STATE_SEED,
            ctx.accounts.state.mint.as_ref(),
            V2_SEED,
            &[state_bump],
        ]];

        if withdraw_amount > 0 {
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
                withdraw_amount,
                ctx.accounts.mint.decimals,
            )?;
        }

        if fee > 0 {
            token_interface::transfer_checked(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    TransferChecked {
                        from: ctx.accounts.vault.to_account_info(),
                        mint: ctx.accounts.mint.to_account_info(),
                        to: ctx.accounts.relayer_fee_ata.to_account_info(),
                        authority: ctx.accounts.state.to_account_info(),
                    },
                    signer_seeds,
                ),
                fee,
                ctx.accounts.mint.decimals,
            )?;
        }

        // Optional change commitment append (tree update happens off-chain via set_root_v2)
        let mut change_index: Option<u32> = None;
        if change_commitment != [0u8; 32] {
            let idx = ctx.accounts.state.next_index;
            ctx.accounts.state.next_index = ctx
                .accounts
                .state
                .next_index
                .checked_add(1)
                .ok_or(IncognitoError::IndexOverflow)?;
            change_index = Some(idx);

            emit!(DepositEventV2 {
                state: ctx.accounts.state.key(),
                mint: ctx.accounts.state.mint,
                commitment: change_commitment,
                index: idx,
                is_change: true,
            });
        }

        emit!(WithdrawEventV2 {
            state: ctx.accounts.state.key(),
            mint: ctx.accounts.state.mint,
            root,
            nullifier_hash,
            withdraw_amount,
            fee,
            recipient: ctx.accounts.destination.owner,
            change_commitment,
            change_index,
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

#[derive(Accounts)]
#[instruction(initial_root: [u8; 32], root_updater: Pubkey)]
pub struct InitializeV2<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(
        init,
        payer = payer,
        space = IncognitoStateV2::SPACE,
        seeds = [STATE_SEED, mint.key().as_ref(), V2_SEED],
        bump
    )]
    pub state: Box<Account<'info, IncognitoStateV2>>,

    #[account(
        init,
        payer = payer,
        seeds = [VAULT_SEED, state.key().as_ref()],
        bump,
        token::mint = mint,
        token::authority = state,
        token::token_program = token_program
    )]
    pub vault: Box<InterfaceAccount<'info, TokenAccount>>,

    pub mint: InterfaceAccount<'info, Mint>,

    pub system_program: Program<'info, System>,
    pub token_program: Interface<'info, TokenInterface>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct SetRootV2<'info> {
    pub root_updater: Signer<'info>,

    #[account(
        mut,
        seeds = [STATE_SEED, state.mint.as_ref(), V2_SEED],
        bump = state.state_bump
    )]
    pub state: Box<Account<'info, IncognitoStateV2>>,
}

#[derive(Accounts)]
#[instruction(commitment: [u8; 32], amount: u64)]
pub struct DepositV2<'info> {
    #[account(mut)]
    pub depositor: Signer<'info>,

    #[account(mut, constraint = depositor_token.owner == depositor.key())]
    pub depositor_token: InterfaceAccount<'info, TokenAccount>,

    #[account(
        mut,
        seeds = [STATE_SEED, state.mint.as_ref(), V2_SEED],
        bump = state.state_bump
    )]
    pub state: Box<Account<'info, IncognitoStateV2>>,

    #[account(mut, seeds = [VAULT_SEED, state.key().as_ref()], bump = state.vault_bump)]
    pub vault: Box<InterfaceAccount<'info, TokenAccount>>,

    pub mint: InterfaceAccount<'info, Mint>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
#[instruction(
    proof: [u8; 256],
    root: [u8; 32],
    nullifier_hash: [u8; 32],
    withdraw_amount: u64,
    fee: u64,
    change_commitment: [u8; 32],
    nullifier_shard_byte: u8,
    nullifier_page_index: u16
)]
pub struct WithdrawV2<'info> {
    #[account(mut)]
    pub relayer: Signer<'info>,

    #[account(
        mut,
        seeds = [STATE_SEED, state.mint.as_ref(), V2_SEED],
        bump = state.state_bump
    )]
    pub state: Box<Account<'info, IncognitoStateV2>>,

    #[account(mut, seeds = [VAULT_SEED, state.key().as_ref()], bump = state.vault_bump)]
    pub vault: Box<InterfaceAccount<'info, TokenAccount>>,

    #[account(
        init_if_needed,
        payer = relayer,
        space = NullifierShard::SPACE,
        seeds = [NULLIFIER_SEED, state.key().as_ref(), &[nullifier_shard_byte]],
        bump
    )]
    pub nullifier_shard: Box<Account<'info, NullifierShard>>,

    #[account(
        init_if_needed,
        payer = relayer,
        space = NullifierPage::SPACE,
        seeds = [NULLIFIER_PAGE_SEED, state.key().as_ref(), &[nullifier_shard_byte], &nullifier_page_index.to_le_bytes()],
        bump
    )]
    pub nullifier_page: AccountLoader<'info, NullifierPage>,

    #[account(mut)]
    pub destination: Box<InterfaceAccount<'info, TokenAccount>>,

    #[account(mut, constraint = relayer_fee_ata.owner == relayer.key())]
    pub relayer_fee_ata: Box<InterfaceAccount<'info, TokenAccount>>,

    pub mint: Box<InterfaceAccount<'info, Mint>>,

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
pub struct IncognitoStateV2 {
    pub mint: Pubkey,
    pub root_updater: Pubkey,
    pub merkle_root: [u8; 32],
    pub next_index: u32,
    pub root_history: [[u8; 32]; ROOT_HISTORY_SIZE],
    pub root_history_cursor: u8,
    pub state_bump: u8,
    pub vault_bump: u8,
}

impl IncognitoStateV2 {
    pub const SPACE: usize = 8 + 32 + 32 + 32 + 4 + (32 * ROOT_HISTORY_SIZE) + 1 + 1 + 1;
}

#[account]
pub struct Nullifier {}

impl Nullifier {
    pub const SPACE: usize = 8;
}

#[account]
pub struct NullifierShard {
    pub state: Pubkey,
    pub shard: u8,
    pub page_count: u16,
    pub bump: u8,
}

impl NullifierShard {
    pub const SPACE: usize = 8 + 32 + 1 + 2 + 1;
}

#[account(zero_copy)]
#[repr(C)]
pub struct NullifierPage {
    pub state: Pubkey,
    pub index: u16,
    pub len: u16,
    pub shard: u8,
    pub bump: u8,
    pub hashes: [[u8; 32]; NULLIFIER_PAGE_CAPACITY],
}

impl NullifierPage {
    pub const SPACE: usize = 8 + core::mem::size_of::<Self>();

    pub fn validate(&self, state: Pubkey, shard: u8, index: u16) -> Result<()> {
        require_keys_eq!(self.state, state, IncognitoError::InvalidNullifierPage);
        require!(self.shard == shard, IncognitoError::InvalidNullifierPage);
        require!(self.index == index, IncognitoError::InvalidNullifierPage);
        Ok(())
    }

    pub fn contains(&self, nullifier_hash: &[u8; 32]) -> bool {
        let n = self.len as usize;
        let max = if n > NULLIFIER_PAGE_CAPACITY { NULLIFIER_PAGE_CAPACITY } else { n };
        for i in 0..max {
            if &self.hashes[i] == nullifier_hash {
                return true;
            }
        }
        false
    }
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
pub struct DepositEventV2 {
    pub state: Pubkey,
    pub mint: Pubkey,
    pub commitment: [u8; 32],
    pub index: u32,
    pub is_change: bool,
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
pub struct RootUpdatedEventV2 {
    pub state: Pubkey,
    pub mint: Pubkey,
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

#[event]
pub struct WithdrawEventV2 {
    pub state: Pubkey,
    pub mint: Pubkey,
    pub root: [u8; 32],
    pub nullifier_hash: [u8; 32],
    pub withdraw_amount: u64,
    pub fee: u64,
    pub recipient: Pubkey,
    pub change_commitment: [u8; 32],
    pub change_index: Option<u32>,
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
    #[msg("Invalid deposit amount (must be > 0).")]
    InvalidDepositAmount,
    #[msg("Unknown Merkle root (not in history).")]
    UnknownRoot,
    #[msg("Invalid nullifier shard (must match nullifier_hash[0]).")]
    InvalidNullifierShard,
    #[msg("Missing required nullifier page account.")]
    MissingNullifierPage,
    #[msg("Nullifier already spent.")]
    NullifierAlreadySpent,
    #[msg("Invalid nullifier page.")]
    InvalidNullifierPage,
    #[msg("Nullifier page full.")]
    NullifierPageFull,
}

#[cfg(test)]
mod tests {
    // Intentionally empty: devnet-first MVP (no local validator/unit-test harness).
}

// -------------------------
// Helpers (v2)
// -------------------------

fn is_known_root(state: &IncognitoStateV2, root: &[u8; 32]) -> bool {
    if &state.merkle_root == root {
        return true;
    }
    for r in state.root_history.iter() {
        if r == root {
            return true;
        }
    }
    false
}

fn u64_to_be_bytes32(v: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&v.to_be_bytes());
    out
}

fn u128_to_be_bytes32(v: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..32].copy_from_slice(&v.to_be_bytes());
    out
}

fn pubkey_to_u128_halves_le(pk: &Pubkey) -> (u128, u128) {
    let b = pk.to_bytes();
    let mut lo = [0u8; 16];
    let mut hi = [0u8; 16];
    lo.copy_from_slice(&b[0..16]);
    hi.copy_from_slice(&b[16..32]);
    (u128::from_le_bytes(lo), u128::from_le_bytes(hi))
}

fn expected_nullifier_page_pda(program_id: &Pubkey, state: Pubkey, shard: u8, index: u16) -> Pubkey {
    Pubkey::find_program_address(
        &[NULLIFIER_PAGE_SEED, state.as_ref(), &[shard], &index.to_le_bytes()],
        program_id,
    )
    .0
}

fn init_or_validate_nullifier_shard(
    shard: &mut Account<NullifierShard>,
    state: Pubkey,
    shard_byte: u8,
    bump: u8,
) -> Result<()> {
    if shard.state == Pubkey::default() {
        shard.state = state;
        shard.shard = shard_byte;
        shard.page_count = 0;
        shard.bump = bump;
        return Ok(());
    }
    require_keys_eq!(shard.state, state, IncognitoError::InvalidNullifierPage);
    require!(shard.shard == shard_byte, IncognitoError::InvalidNullifierPage);
    Ok(())
}

fn init_or_validate_nullifier_page(
    page: &mut NullifierPage,
    state: Pubkey,
    shard_byte: u8,
    index: u16,
    bump: u8,
) -> Result<()> {
    if page.state == Pubkey::default() {
        page.state = state;
        page.shard = shard_byte;
        page.index = index;
        page.len = 0;
        page.bump = bump;
        return Ok(());
    }
    page.validate(state, shard_byte, index)
}

fn nullifier_page_contains_and_len(
    ai: &AccountInfo,
    state: Pubkey,
    shard: u8,
    index: u16,
    nullifier_hash: &[u8; 32],
) -> Result<(u16, bool)> {
    use anchor_lang::Discriminator;

    // Minimal parsing to avoid copying the whole `hashes` array onto the stack.
    let data = ai.data.borrow();
    // NullifierPage field order avoids padding (Pod requirement).
    let header_len = 8 + 32 + 2 + 2 + 1 + 1;
    require!(data.len() >= header_len, IncognitoError::InvalidNullifierPage);
    require!(
        data[0..8] == NullifierPage::discriminator(),
        IncognitoError::InvalidNullifierPage
    );

    let state_off = 8;
    let index_off = state_off + 32;
    let len_off = index_off + 2;
    let shard_off = len_off + 2;
    let bump_off = shard_off + 1;
    let hashes_off = bump_off + 1;

    let page_state = Pubkey::new_from_array(data[state_off..state_off + 32].try_into().unwrap());
    require_keys_eq!(page_state, state, IncognitoError::InvalidNullifierPage);

    let page_index = u16::from_le_bytes(data[index_off..index_off + 2].try_into().unwrap());
    require!(page_index == index, IncognitoError::InvalidNullifierPage);

    let len = u16::from_le_bytes(data[len_off..len_off + 2].try_into().unwrap());
    require!(data[shard_off] == shard, IncognitoError::InvalidNullifierPage);
    let max = std::cmp::min(len as usize, NULLIFIER_PAGE_CAPACITY);
    let needed = 8 + core::mem::size_of::<NullifierPage>();
    require!(data.len() >= needed, IncognitoError::InvalidNullifierPage);

    for i in 0..max {
        let off = hashes_off + (i * 32);
        if &data[off..off + 32] == nullifier_hash {
            return Ok((len, true));
        }
    }

    Ok((len, false))
}
